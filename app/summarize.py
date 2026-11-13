"""DeepSeek 可选增强:对重要漏洞生成中文摘要。默认关闭,不影响主链路。"""
import logging

import requests

from . import config

logger = logging.getLogger("vulnwatch")

API_URL = "https://api.deepseek.com/chat/completions"


def _field(v, name, default=None):
    """兼容 ORM 对象与 dict 两种数据形态。"""
    if isinstance(v, dict):
        return v.get(name, default)
    return getattr(v, name, default)


def summarize_vuln(api_key: str, vuln) -> str:
    """调用 DeepSeek 生成一条漏洞的中文摘要。失败返回空字符串。"""
    if not api_key:
        return ""
    cve = _field(vuln, "cve_id") or _field(vuln, "unique_key") or "未知"
    desc = (_field(vuln, "description") or _field(vuln, "title") or "")[:1500]
    prompt = (
        f"你是企业安全运维助手。请用简洁中文(不超过80字)总结以下漏洞的核心风险与修复建议。\n"
        f"漏洞编号: {cve}\n"
        f"严重等级: {_field(vuln, 'severity')}\n"
        f"CVSS评分: {_field(vuln, 'cvss_score') or '未知'}\n"
        f"描述: {desc}\n"
    )
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": config.AI_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 200,
        "temperature": 0.3,
    }
    try:
        resp = requests.post(API_URL, json=payload, headers=headers, timeout=config.AI_TIMEOUT)
        if resp.status_code != 200:
            logger.debug("DeepSeek 摘要失败: HTTP %s", resp.status_code)
            return ""
        data = resp.json()
        content = (data.get("choices") or [{}])[0].get("message", {}).get("content") or ""
        return content.strip()[:500]
    except Exception as e:
        logger.debug("DeepSeek 摘要异常: %s", e)
        return ""
