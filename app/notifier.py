"""多渠道通知模块。

已实现:钉钉(默认)、企业微信、飞书、Server券、PushPlus。
通过 settings 里的 `notify_channel` 决定用哪个通道;
新增通道只需:实现一个 send_xxx 函数 → 在 CHANNELS 注册表登记。

优化点:
1. 报告自动分片:钉钉上限 20000 字节、企微 4096 字节,原实现一次性发送,
   条数多时（50 条 × 长标题）会超限导致整条推送失败;现在按 PUSH_MAX_BYTES 分条。
2. 发送失败不再静默吞掉,统一记录日志,便于排障。
3. 每条漏洞可带 DeepSeek 生成的一句话摘要（ai_summary）。
"""
import base64
import hashlib
import hmac
import logging
import time
import urllib.parse
from typing import Iterable, List

import requests

from . import config

logger = logging.getLogger("vulnwatch")


# ---------- 钉钉 ----------

def _sign_dingtalk(secret: str):
    timestamp = str(round(time.time() * 1000))
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(
        secret.encode("utf-8"), string_to_sign.encode("utf-8"), digestmod=hashlib.sha256
    ).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    return timestamp, sign


def send_dingtalk(webhook: str, secret: str, title: str, text: str) -> bool:
    if secret:
        timestamp, sign = _sign_dingtalk(secret)
        webhook = f"{webhook}&timestamp={timestamp}&sign={sign}"
    payload = {"msgtype": "markdown", "markdown": {"title": title, "text": text}}
    resp = requests.post(webhook, json=payload, timeout=config.REQUEST_TIMEOUT)
    data = resp.json()
    ok = data.get("errcode") == 0
    if not ok:
        logger.warning("钉钉推送失败: %s", data)
    return ok


# ---------- 企业微信 ----------

def send_wecom(webhook: str, secret: str, title: str, text: str) -> bool:
    payload = {"msgtype": "markdown", "markdown": {"content": text}}
    resp = requests.post(webhook, json=payload, timeout=config.REQUEST_TIMEOUT)
    data = resp.json()
    ok = data.get("errcode") == 0
    if not ok:
        logger.warning("企业微信推送失败: %s", data)
    return ok


# ---------- 飞书 ----------

def send_feishu(webhook: str, secret: str, title: str, text: str) -> bool:
    payload = {"msg_type": "text", "content": {"text": text}}
    if secret:
        timestamp = str(int(time.time()))
        string_to_sign = f"{timestamp}\n{secret}"
        # 注意:hmac.new(key, msg, ...) 第一个参数是密钥、第二个才是待签名消息。
        # 之前把消息当成了 key 且未传 msg,签名错误,飞书开启加签校验时会拒绝推送。
        hmac_code = hmac.new(
            secret.encode("utf-8"), string_to_sign.encode("utf-8"), digestmod=hashlib.sha256
        ).digest()
        payload["timestamp"] = timestamp
        payload["sign"] = base64.b64encode(hmac_code).decode("utf-8")
    resp = requests.post(webhook, json=payload, timeout=config.REQUEST_TIMEOUT)
    data = resp.json()
    ok = data.get("StatusCode") == 0 or data.get("code") == 0
    if not ok:
        logger.warning("飞书推送失败: %s", data)
    return ok


# ---------- Server酱 ----------

def send_serverchan(sendkey: str, secret: str, title: str, text: str) -> bool:
    url = f"https://sctapi.ftqq.com/{sendkey}.send"
    resp = requests.post(url, data={"title": title, "desp": text}, timeout=config.REQUEST_TIMEOUT)
    data = resp.json()
    ok = data.get("code") == 0
    if not ok:
        logger.warning("Server酱推送失败: %s", data)
    return ok


# ---------- PushPlus ----------

def send_pushplus(token: str, secret: str, title: str, text: str) -> bool:
    payload = {"token": token, "title": title, "content": text, "template": "markdown"}
    resp = requests.post(
        "https://www.pushplus.plus/send", json=payload, timeout=config.REQUEST_TIMEOUT
    )
    data = resp.json()
    ok = data.get("code") == 200
    if not ok:
        logger.warning("PushPlus 推送失败: %s", data)
    return ok


CHANNELS = {
    "dingtalk": send_dingtalk,
    "wecom": send_wecom,
    "feishu": send_feishu,
    "serverchan": send_serverchan,
    "pushplus": send_pushplus,
}

# 通道 -> (凭证配置键, 加签密钥配置键)
CHANNEL_KEYS = {
    "dingtalk": ("dingtalk_webhook", "dingtalk_secret"),
    "wecom": ("wecom_webhook", "wecom_secret"),
    "feishu": ("feishu_webhook", "feishu_secret"),
    "serverchan": ("serverchan_sendkey", ""),
    "pushplus": ("pushplus_token", ""),
}


def send(channel: str, credential: str, secret: str, title: str, text: str) -> bool:
    """发送通知,返回是否成功。未知通道/缺凭证返回 False。"""
    fn = CHANNELS.get(channel)
    if not fn or not credential:
        logger.warning("推送通道不可用: channel=%s, 凭证是否为空=%s", channel, not credential)
        return False
    try:
        return bool(fn(credential, secret, title, text))
    except Exception as e:
        # Request exception messages can contain the full signed webhook URL.
        logger.warning("推送异常(%s): %s", channel, type(e).__name__)
        return False


# ---------- 报告生成 ----------

_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
_LEVEL_SECTIONS = (
    ("CRITICAL", "🔴 严重"),
    ("HIGH", "🟠 高危"),
    ("MEDIUM", "🟡 中危"),
    ("LOW", "🟢 低危"),
)


def _field(v, name, default=None):
    """兼容 ORM 对象与 dict 两种数据形态。"""
    if isinstance(v, dict):
        return v.get(name, default)
    return getattr(v, name, default)


def _render_item(v) -> List[str]:
    """把一条漏洞渲染为 markdown 行。"""
    cve = _field(v, "cve_id") or _field(v, "unique_key") or "公告"
    title = (_field(v, "title") or "")[:80]
    cvss = _field(v, "cvss_score")
    tags = _field(v, "tags")
    affected = _field(v, "affected")
    url = _field(v, "url")
    ai = _field(v, "ai_summary")

    head = f"- **{cve}**"
    if cvss:
        head += f" (CVSS {cvss})"
    head += f" — {title}"
    if tags:
        head += f" `{tags}`"
    lines = [head]
    if affected:
        lines.append(f"  - 受影响: {str(affected)[:100]}")
    if url:
        lines.append(f"  - [详情]({url})")
    if ai:
        lines.append(f"  - AI: {str(ai)[:200]}")
    return lines


def _chunk_text(text: str, max_bytes: int) -> List[str]:
    """按行切分文本,保证每片 UTF-8 字节数不超过 max_bytes。"""
    parts: List[str] = []
    cur: List[str] = []
    size = 0
    for line in text.split("\n"):
        line_bytes = len(line.encode("utf-8")) + 1
        if cur and size + line_bytes > max_bytes:
            parts.append("\n".join(cur))
            cur, size = [], 0
        cur.append(line)
        size += line_bytes
    if cur:
        parts.append("\n".join(cur))
    return parts


def build_report_batches(vulns, threshold_severity="HIGH", max_items=None, report_title="每日漏洞情报汇总"):
    """Keep each record in one message so successful chunks can be acknowledged."""
    items = sorted(list(vulns or []), key=lambda v: (
        0 if _field(v, "is_kev") else 1,
        _RANK.get((_field(v, "severity") or "UNKNOWN").upper(), 4),
        -(_field(v, "cvss_score") or 0),
    ))
    if max_items is not None:
        items = items[:max_items]
    if not items:
        return []
    budget = max(256, config.PUSH_MAX_BYTES - 600)
    groups, blocks, records, size = [], [], [], 0
    for v in items:
        label = "🚨 在野利用" if _field(v, "is_kev") else str(_field(v, "severity") or "UNKNOWN")
        block = "### " + label + chr(10) + chr(10).join(_render_item(v))
        encoded = block.encode("utf-8")
        if len(encoded) > budget:
            block = encoded[:budget - 3].decode("utf-8", errors="ignore") + "…"
        block_size = len(block.encode("utf-8")) + 2
        if blocks and size + block_size > budget:
            groups.append((blocks, records))
            blocks, records, size = [], [], 0
        blocks.append(block)
        records.append(v)
        size += block_size
    if blocks:
        groups.append((blocks, records))
    now = config.now_local().strftime("%Y-%m-%d %H:%M")
    result = []
    for idx, (blocks, records) in enumerate(groups, 1):
        header = (f"## 🔒 {report_title} (第 {idx}/{len(groups)} 部分)" + chr(10)
                  + f"共 {len(items)} 条需要关注 (阈值 {threshold_severity.upper()}) · {now}")
        result.append((header + chr(10)*2 + (chr(10)*2).join(blocks), records))
    return result


def build_report_messages(vulns: Iterable, threshold_severity="HIGH", max_items=None) -> List[str]:
    return [text for text, _ in build_report_batches(vulns, threshold_severity, max_items)]


def build_report(vulns, threshold_severity: str = "HIGH", max_items: int = 50) -> str:
    """兼容旧接口:合并为单条文本(超长时仍建议用 build_report_messages 分片发送)。"""
    return "\n\n".join(build_report_messages(vulns, threshold_severity, max_items))
