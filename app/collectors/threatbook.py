"""微步在线研究响应中心采集器(https://x.threatbook.com/v5/vulIntelligence)。

参考 watchvuln 实现:走 API 接口,过滤条件为「高危 且 有Poc 且 有漏洞分析 且 两周内」。
"""
from datetime import datetime, timedelta
from typing import List

from .. import config
from .base import BaseCollector

API = "https://x.threatbook.com/v5/node/vul_module/homePage"


class ThreatbookCollector(BaseCollector):
    source_type = "threatbook"

    def collect(self) -> List[dict]:
        headers = {
            "Referer": "https://x.threatbook.com/v5/vulIntelligence",
            "Origin": "https://mp.weixin.qq.com/",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        }
        resp = self._http_get(API, headers=headers)
        if resp.status_code != 200:
            return []
        data = resp.json()
        high_risk = data.get("data", {}).get("highrisk", [])
        results = []
        for v in high_risk:
            info = self._normalize(v)
            if info:
                results.append(info)
        return results

    def _normalize(self, v: dict) -> dict:
        tags = []
        if v.get("is0day"):
            tags.append("0day")
        has_poc = bool(v.get("pocExist"))
        if has_poc:
            tags.append("有Poc")
        has_analysis = bool(v.get("premium"))
        if has_analysis:
            tags.append("有漏洞分析")
        if v.get("solution"):
            tags.append("有修复方案")

        disclosure = v.get("vuln_publish_time") or v.get("vuln_update_time") or ""

        # 过滤:必须有 Poc(有漏洞分析字段在当前接口已恒为 False,不再作为硬条件)
        if not has_poc:
            return None
        if not disclosure:
            return None
        try:
            dis = datetime.strptime(disclosure, "%Y-%m-%d")
        except (ValueError, TypeError):
            return None
        # 以 vuln_update_time(最近更新)为参考,放宽到 30 天,避免漏报仍在活跃的漏洞
        update = v.get("vuln_update_time") or disclosure
        try:
            upd = datetime.strptime(update, "%Y-%m-%d")
        except (ValueError, TypeError):
            upd = dis
        if config.utcnow() - upd > timedelta(days=30):
            return None

        return {
            "cve_id": None,
            "unique_key": v.get("id") or v.get("vuln_name_zh"),
            "title": v.get("vuln_name_zh") or "",
            "description": None,
            "severity": "CRITICAL",  # 高危池,微步本身无细分等级,按严重处理
            "cvss_score": None,
            "affected": "; ".join(v.get("affects") or []) or None,
            "tags": ",".join(tags) if tags else None,
            "url": (f"https://x.threatbook.com/v5/vul/{v.get('id')}"
                    if v.get("id") else "https://x.threatbook.com/v5/vulIntelligence"),
            "published_at": dis,
            "is_kev": False,
        }
