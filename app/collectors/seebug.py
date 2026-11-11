"""知道创宇 Seebug 漏洞平台采集器(https://www.seebug.org)。

参考 watchvuln 实现:解析 HTML 列表页,过滤条件为「高危」。
"""
import re
from datetime import datetime
from typing import List

from .base import BaseCollector

LIST_URL = "https://www.seebug.org/vuldb/vulnerabilities"


class SeebugCollector(BaseCollector):
    source_type = "seebug"

    def collect(self) -> List[dict]:
        results = []
        # 解析前 3 页
        for page in range(1, 4):
            url = LIST_URL if page == 1 else f"{LIST_URL}?page={page}"
            resp = self._http_get(url, headers={"Referer": "https://www.seebug.org/"})
            if resp.status_code != 200:
                break
            items = self._parse_page(resp.text)
            if not items:
                break
            results.extend(items)
        return results

    def _parse_page(self, html: str) -> List[dict]:
        results = []
        # 每条漏洞是一个 <tr>,含 6 个 td:编号/披露时间/等级/标题/CVE/详情
        rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.S)
        for row in rows:
            tds = re.findall(r"<td[^>]*>(.*?)</td>", row, re.S)
            if len(tds) < 5:
                continue
            # td0: SSV 编号链接
            id_m = re.search(r'href="([^"]+)"[^>]*>([^<]+)</a>', tds[0])
            if not id_m:
                continue
            href = id_m.group(1).strip()
            ssv_id = id_m.group(2).strip()
            url = href if href.startswith("http") else f"https://www.seebug.org{href}"

            # td1: 披露时间
            disclosure = re.sub(r"<[^>]+>", "", tds[1]).strip()

            # td2: 等级 (data-original-title)
            sev_m = re.search(r'data-original-title="([^"]+)"', tds[2])
            sev_title = sev_m.group(1).strip() if sev_m else ""
            severity_map = {"高危": "HIGH", "中危": "MEDIUM", "低危": "LOW"}
            severity = severity_map.get(sev_title, "UNKNOWN")

            # 过滤:仅高危
            if severity != "HIGH":
                continue

            # td3: 标题
            title = re.sub(r"<[^>]+>", "", tds[3]).strip()

            # td4: CVE 编号 (data-original-title)
            cve_m = re.search(r'data-original-title="([^"]+)"', tds[4])
            cve_id = None
            if cve_m:
                cve_raw = cve_m.group(1).strip()
                # 可能多个 CVE 用、分隔
                cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", cve_raw)
                if cve_list:
                    cve_id = cve_list[0]

            published = None
            if disclosure:
                try:
                    published = datetime.strptime(disclosure, "%Y-%m-%d")
                except ValueError:
                    published = None

            results.append({
                "cve_id": cve_id,
                "unique_key": ssv_id or f"SSV-{cve_id}",
                "title": title or ssv_id,
                "description": None,
                "severity": severity,
                "cvss_score": None,
                "affected": None,
                "tags": "Seebug",
                "url": url,
                "published_at": published,
                "is_kev": False,
            })
        return results
