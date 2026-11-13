"""奇安信威胁情报中心采集器(https://ti.qianxin.com/)。

参考 watchvuln 实现:走 API 接口,过滤条件为「高危/极危 且 包含
奇安信CERT验证 / POC公开 / EXP公开 / 技术细节公布 标签之一」。
"""
from datetime import datetime
from typing import List

from .base import BaseCollector

API = "https://ti.qianxin.com/alpha-api/v2/vuln/one-day"

VALUABLE_TAGS = {"奇安信CERT验证", "POC公开", "EXP公开", "技术细节公布"}


class QianxinTiCollector(BaseCollector):
    source_type = "qianxin_ti"

    def collect(self) -> List[dict]:
        headers = {
            "Referer": "https://ti.qianxin.com/",
            "Origin": "https://ti.qianxin.com",
        }
        resp = self._http_post(API, headers=headers)
        if resp.status_code != 200:
            return []
        data = resp.json()
        key_vulns = data.get("data", {}).get("key_vuln_add", [])
        results = []
        seen = set()
        for d in key_vulns:
            info = self._normalize(d)
            if info and info["unique_key"] not in seen:
                seen.add(info["unique_key"])
                results.append(info)
        return results

    def _normalize(self, d: dict) -> dict:
        severity_map = {"低危": "LOW", "中危": "MEDIUM", "高危": "HIGH", "极危": "CRITICAL"}
        severity = severity_map.get(d.get("rating_level"), "UNKNOWN")

        tags = [t.get("name", "").strip() for t in (d.get("tag") or [])]
        tags = [t for t in tags if t]

        # 过滤:高危/极危 且 含指定标签之一
        if severity not in ("HIGH", "CRITICAL"):
            return None
        if not any(t in VALUABLE_TAGS for t in tags):
            return None

        published = None
        pub = d.get("publish_time")
        if pub:
            try:
                published = datetime.strptime(pub, "%Y-%m-%d")
            except (ValueError, TypeError):
                try:
                    published = datetime.fromisoformat(str(pub).replace("Z", "+00:00")).replace(tzinfo=None)
                except (ValueError, TypeError):
                    published = None

        return {
            "cve_id": d.get("cve_code") or None,
            "unique_key": d.get("qvd_code") or f"QX-{d.get('id')}",
            "title": d.get("vuln_name") or "",
            "description": d.get("description"),
            "severity": severity,
            "cvss_score": None,
            "affected": None,
            "tags": ",".join(tags) if tags else None,
            "url": f"https://ti.qianxin.com/vulnerability/detail/{d.get('id')}",
            "published_at": published,
            "is_kev": False,
        }
