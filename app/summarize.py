"""DeepSeek 可选增强:对重要漏洞生成中文摘要。默认关闭,不影响主链路。"""
import requests

from . import config

API_URL = "https://api.deepseek.com/chat/completions"


def summarize_vuln(api_key: str, vuln) -> str:
    """调用 DeepSeek 生成一条漏洞的中文摘要。失败返回空字符串。"""
    if not api_key:
        return ""
    cve = vuln.cve_id or "未知"
    desc = (vuln.description or vuln.title or "")[:1500]
    prompt = (
        f"你是企业安全运维助手。请用简洁中文(不超过80字)总结以下漏洞的核心风险与修复建议。\n"
        f"漏洞编号: {cve}\n"
        f"严重等级: {vuln.severity}\n"
        f"CVSS评分: {vuln.cvss_score or '未知'}\n"
        f"描述: {desc}\n"
    )
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 200,
        "temperature": 0.3,
    }
    try:
        resp = requests.post(API_URL, json=payload, headers=headers, timeout=config.REQUEST_TIMEOUT)
        if resp.status_code != 200:
            return ""
        data = resp.json()
        return data["choices"][0]["message"]["content"].strip()
    except Exception:
        return ""
