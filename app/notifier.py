"""多渠道通知模块。

默认支持钉钉(已实现),并预留企微、飞书、Server酱、PushPlus 等通道的
发送函数与配置入口,通过 settings 里的 `notify_channel` 决定用哪个通道。
新增通道只需:实现一个 send_xxx 函数 → 在 CHANNELS 注册表登记。
"""
import base64
import hashlib
import hmac
import time
import urllib.parse

import requests

from . import config


# ---------- 钉钉 ----------

def _sign_dingtalk(secret: str) -> tuple:
    """钉钉加签:返回 (timestamp, sign)。"""
    timestamp = str(round(time.time() * 1000))
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(secret.encode("utf-8"), string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    return timestamp, sign


def send_dingtalk(webhook: str, secret: str, title: str, text: str) -> bool:
    """发送 markdown 消息到钉钉。"""
    if not webhook:
        return False
    url = webhook
    if secret:
        timestamp, sign = _sign_dingtalk(secret)
        sep = "&" if "?" in url else "?"
        url = f"{url}{sep}timestamp={timestamp}&sign={sign}"
    payload = {"msgtype": "markdown", "markdown": {"title": title, "text": text}}
    try:
        resp = requests.post(url, json=payload, timeout=config.REQUEST_TIMEOUT)
        return resp.json().get("errcode") == 0
    except Exception:
        return False


# ---------- 预留通道(接口已就位,按需填凭证即可用) ----------

def send_wecom(webhook: str, secret: str, title: str, text: str) -> bool:
    """企业微信群机器人。预留:webhook 为群机器人地址,secret 留作扩展。"""
    if not webhook:
        return False
    payload = {"msgtype": "markdown", "markdown": {"content": text}}
    try:
        resp = requests.post(webhook, json=payload, timeout=config.REQUEST_TIMEOUT)
        return resp.json().get("errcode") == 0
    except Exception:
        return False


def send_feishu(webhook: str, secret: str, title: str, text: str) -> bool:
    """飞书自定义机器人。预留:secret 为飞书签名校验(可选)。"""
    if not webhook:
        return False
    payload = {"msg_type": "text", "content": {"text": f"{title}\n{text}"}}
    if secret:
        timestamp = str(int(time.time()))
        string_to_sign = f"{timestamp}\n{secret}"
        hmac_code = hmac.new(string_to_sign.encode("utf-8"), digestmod=hashlib.sha256).digest()
        sign = base64.b64encode(hmac_code).decode("utf-8")
        payload["timestamp"] = timestamp
        payload["sign"] = sign
    try:
        resp = requests.post(webhook, json=payload, timeout=config.REQUEST_TIMEOUT)
        d = resp.json()
        return d.get("code") == 0 or d.get("StatusCode") == 0 or d.get("status_code") == 0
    except Exception:
        return False


def send_serverchan(sendkey: str, secret: str, title: str, text: str) -> bool:
    """Server酱(方糖)推送。预留:sendkey 为 SendKey。"""
    if not sendkey:
        return False
    url = f"https://sctapi.ftqq.com/{sendkey}.send"
    try:
        resp = requests.post(url, data={"title": title, "desp": text}, timeout=config.REQUEST_TIMEOUT)
        return resp.json().get("code") == 0
    except Exception:
        return False


def send_pushplus(token: str, secret: str, title: str, text: str) -> bool:
    """PushPlus 推送。预留:token 为 PushPlus token。"""
    if not token:
        return False
    url = "https://www.pushplus.plus/send"
    try:
        resp = requests.post(url, json={"token": token, "title": title, "content": text}, timeout=config.REQUEST_TIMEOUT)
        return resp.json().get("code") == 200
    except Exception:
        return False


# ---------- 通道注册表与统一入口 ----------

CHANNELS = {
    "dingtalk": send_dingtalk,
    "wecom": send_wecom,
    "feishu": send_feishu,
    "serverchan": send_serverchan,
    "pushplus": send_pushplus,
}

# 各通道所需的凭证配置键名(webhook / token 键, secret 键)
CHANNEL_KEYS = {
    "dingtalk": ("dingtalk_webhook", "dingtalk_secret"),
    "wecom": ("wecom_webhook", "wecom_secret"),
    "feishu": ("feishu_webhook", "feishu_secret"),
    "serverchan": ("serverchan_sendkey", ""),
    "pushplus": ("pushplus_token", ""),
}


def send(channel: str, credential: str, secret: str, title: str, text: str) -> bool:
    """统一发送入口:按通道名路由到对应发送函数。"""
    fn = CHANNELS.get(channel)
    if not fn:
        return False
    return fn(credential, secret or "", title, text)


# ---------- 报告组装 ----------

def build_report(vulns, threshold_severity: str = "HIGH", max_items: int = 50) -> str:
    """将漏洞列表组装成 markdown 文本,按等级分组,重要漏洞置顶高亮。

    max_items: 每条消息最多展示的漏洞数(钉钉单条消息有长度限制)。
    """
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulns = sorted(vulns, key=lambda v: (rank.get(v.severity, 4), -(v.cvss_score or 0)))
    total = len(vulns)

    lines = [
        "## 🔒 每日漏洞情报汇总",
        f"> 共 **{total}** 条,自动采集于 {time.strftime('%Y-%m-%d %H:%M')}",
        "",
    ]

    shown = 0

    # 在野利用(KEV)单独高亮置顶
    kev = [v for v in vulns if v.is_kev]
    if kev:
        lines.append(f"### 🚨 在野利用(需立即处理,共 {len(kev)} 条)")
        lines.append("")
        for v in kev[:max_items]:
            lines.append(f"- **{v.cve_id or v.title}** — {v.title[:80]}")
            if v.affected:
                lines.append(f"  - 受影响: {v.affected[:100]}")
            if v.url:
                lines.append(f"  - [详情]({v.url})")
            shown += 1
        lines.append("")

    # 按等级分组
    for level, label, emoji in [
        ("CRITICAL", "严重", "🔴"),
        ("HIGH", "高危", "🟠"),
        ("MEDIUM", "中危", "🟡"),
        ("LOW", "低危", "🟢"),
    ]:
        if shown >= max_items:
            break
        group = [v for v in vulns if v.severity == level and not v.is_kev]
        if not group:
            continue
        lines.append(f"### {emoji} {label}({len(group)})")
        lines.append("")
        for v in group[: max_items - shown]:
            score = f" CVSS {v.cvss_score}" if v.cvss_score else ""
            tag = f" `{v.tags}`" if v.tags else ""
            lines.append(f"- **{v.cve_id or '公告'}**{score} — {v.title[:80]}{tag}")
            if v.url:
                lines.append(f"  - [详情]({v.url})")
            shown += 1
        lines.append("")

    if total > shown:
        lines.append(f"> 仅展示前 {shown} 条,完整 {total} 条请查看 Web 管理界面")
    else:
        lines.append("> 完整列表请查看 Web 管理界面")
    return "\n".join(lines)
