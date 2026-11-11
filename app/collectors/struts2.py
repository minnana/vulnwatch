"""Apache Struts2 安全公告采集器。

参考 watchvuln 实现:解析 Confluence 页面,过滤条件为「高危(Important)/严重(Critical)」。
"""
import re
from typing import List

from .base import BaseCollector

BULLETINS_URL = "https://cwiki.apache.org/confluence/display/WW/Security+Bulletins"


class Struts2Collector(BaseCollector):
    source_type = "struts2"

    def collect(self) -> List[dict]:
        headers = {
            "Referer": "https://cwiki.apache.org/",
            "Origin": "https://cwiki.apache.org/",
            "Accept-Language": "en-US,en;q=0.9",
        }
        resp = self._http_get(BULLETINS_URL, headers=headers)
        if resp.status_code != 200:
            return []
        html = resp.text

        # 提取所有 S2-xxx 链接(链接在 href 中,标题在 title 属性)
        items = re.findall(r'href="([^"]*(S2-\d{3})[^"]*)"', html)
        results = []
        seen = set()
        for href, s2id in items:
            if s2id in seen:
                continue
            seen.add(s2id)
            results.append({"href": href, "s2id": s2id})
            if len(results) >= 20:
                break

        # 逐个详情页解析严重性
        vulns = []
        for r in results[-10:]:  # 最近 10 条
            detail = self._parse_detail(r["href"], r["s2id"])
            if detail:
                vulns.append(detail)
        return vulns

    def _parse_detail(self, href: str, s2id: str) -> dict:
        full = href if href.startswith("http") else f"https://cwiki.apache.org{href}"
        resp = self._http_get(full)
        if resp.status_code != 200:
            return None
        html = resp.text

        # Maximum security rating: 取 severity(HTML 中 th/td 内含 <p> 标签)
        sev_m = re.search(r"Maximum security rating</p>\s*</th>\s*<td[^>]*>\s*<p>([^<]+)</p>", html, re.S)
        if not sev_m:
            sev_m = re.search(r"Maximum security rating</th>\s*<td[^>]*>([^<]+)</td>", html, re.S)
        sev_text = sev_m.group(1).strip() if sev_m else ""
        severity_map = {"critical": "CRITICAL", "important": "HIGH", "moderate": "MEDIUM", "low": "LOW"}
        severity = severity_map.get(sev_text.lower(), "LOW")

        # 过滤:仅高危/严重
        if severity not in ("HIGH", "CRITICAL"):
            return None

        # CVE
        cve_m = re.search(r"CVE Identifier</p>\s*</th>\s*<td[^>]*>\s*(?:<p>)?([^<]+)", html, re.S)
        if not cve_m:
            cve_m = re.search(r"CVE Identifier</th>\s*<td[^>]*>([^<]+)</td>", html, re.S)
        cve_id = None
        if cve_m:
            cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", cve_m.group(1))
            if cve_list:
                cve_id = cve_list[0]

        # 描述
        desc_m = re.search(r'(?:-Problem|Problem)</h2>\s*<p>(.*?)</p>', html, re.S)
        description = re.sub(r"<[^>]+>", "", desc_m.group(1)).strip() if desc_m else None

        # 影响
        impact_m = re.search(r"Impact of vulnerability</p>\s*</th>\s*<td[^>]*>\s*<p>([^<]+)</p>", html, re.S)
        if not impact_m:
            impact_m = re.search(r"Impact of vulnerability</th>\s*<td[^>]*>([^<]+)</td>", html, re.S)
        impact = impact_m.group(1).strip() if impact_m else None

        return {
            "cve_id": cve_id,
            "unique_key": s2id,
            "title": s2id,
            "description": description,
            "severity": severity,
            "cvss_score": None,
            "affected": "Apache Struts2",
            "tags": f"Struts2,{impact}" if impact else "Struts2",
            "url": full,
            "published_at": None,
            "is_kev": False,
        }
