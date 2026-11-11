"""长亭漏洞库采集器(https://stack.chaitin.com/vuldb/index)。

参考 watchvuln 实现:走 API 接口,过滤条件为「高危/严重 且 标题含中文」。
"""
import re
from datetime import datetime
from typing import List

from .base import BaseCollector

API = "https://stack.chaitin.com/api/v2/vuln/list/"


def _contains_chinese(s: str) -> bool:
    return bool(re.search(r"[\u4e00-\u9fff]", s or ""))


class ChaitinCollector(BaseCollector):
    source_type = "chaitin"

    def collect(self) -> List[dict]:
        results = []
        headers = {
            "Referer": "https://stack.chaitin.com/vuldb/index",
            "Origin": "https://stack.chaitin.com",
        }
        # 拉取前 3 页,每页 15 条
        for i in range(3):
            url = f"{API}?limit=15&offset={i * 15}&search=CT-"
            resp = self._http_get(url, headers=headers)
            if resp.status_code != 200:
                break
            data = resp.json()
            items = data.get("data", {}).get("list", [])
            if not items:
                break
            for d in items:
                info = self._normalize(d)
                if info:
                    results.append(info)
        return results

    def _normalize(self, d: dict) -> dict:
        severity_map = {"low": "LOW", "medium": "MEDIUM", "high": "HIGH", "critical": "CRITICAL"}
        severity = severity_map.get((d.get("severity") or "").lower(), "UNKNOWN")

        title = d.get("title") or ""
        summary = d.get("summary") or ""
        cve_id = d.get("cve_id")

        # 过滤:仅高危/严重
        if severity not in ("HIGH", "CRITICAL"):
            return None
        # 过滤:中文内容(标题或描述)含中文 —— 适配当前 API 版本(title 可能为 CVE 编号)
        if not _contains_chinese(title) and not _contains_chinese(summary):
            return None

        # cvss3 可能是 dict(向量)或数字
        cvss = d.get("cvss3") or d.get("cvss2")
        if isinstance(cvss, dict):
            cvss = None

        published = None
        created = d.get("created_at")
        if created:
            try:
                published = datetime.fromisoformat(str(created).replace("Z", "+00:00")).replace(tzinfo=None)
            except (ValueError, TypeError):
                published = None

        # 展示标题优先用中文摘要首句,否则用 CVE/CT 编号
        display_title = summary[:80] if _contains_chinese(summary) else (title or cve_id or d.get("ct_id"))

        return {
            "cve_id": cve_id or None,
            "unique_key": d.get("ct_id") or f"CT-{d.get('id')}",
            "title": display_title,
            "description": summary,
            "severity": severity,
            "cvss_score": cvss,
            "affected": None,
            "tags": "长亭,中文",
            "url": f"https://stack.chaitin.com/vuldb/detail/{d.get('id')}",
            "published_at": published,
            "is_kev": False,
        }
