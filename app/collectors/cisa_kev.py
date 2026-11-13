"""CISA KEV(已知在野利用漏洞)采集器。"""
from datetime import datetime
from typing import List

from .base import BaseCollector


class CisaKevCollector(BaseCollector):
    """拉取 CISA KEV 目录,这些漏洞已被确认在野利用,必须高亮。"""

    source_type = "cisa_kev"
    URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def collect(self) -> List[dict]:
        resp = self._http_get(self.URL)
        if resp.status_code != 200:
            return []
        data = resp.json()
        results = []
        for item in data.get("vulnerabilities", []):
            results.append(self._normalize(item))
        return results

    def _normalize(self, item: dict) -> dict:
        cve_id = item.get("cveID", "")
        vuln_name = item.get("vulnerabilityName", "")
        short_desc = item.get("shortDescription", "")
        added = item.get("dateAdded", "")
        due_date = item.get("dueDate", "")
        product = item.get("product", "")
        vendor = item.get("vendorProject", "")

        # KEV 无 CVSS,但"在野利用"一律按最高优先级处理
        title = vuln_name or cve_id
        desc = f"{short_desc} (厂商: {vendor or '未知'}, 产品: {product or '未知'}, 修复期限: {due_date or '未知'})"

        added_at = None
        try:
            added_at = datetime.strptime(added, "%Y-%m-%d") if added else None
        except ValueError:
            added_at = None

        return {
            "unique_key": cve_id or None,
            "cve_id": cve_id,
            "title": title,
            "description": desc,
            "severity": "CRITICAL",  # 在野利用视为最高优先级
            "cvss_score": None,
            "affected": f"{vendor or ''} {product or ''}".strip() or None,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "published_at": added_at,
            "is_kev": True,
        }
