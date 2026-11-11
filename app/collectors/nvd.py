"""NVD CVE API 2.0 采集器:按关键词搜索 + 日期范围拉取。

说明:NVD 的 cpeName 参数不接受通配版本号(用 `*` 会 404),
因此监控"整个产品线"时改用 keywordSearch(按产品名关键词搜索)。
如需精确到某版本,可在 URL 上使用 cpeName=...:版本号。
"""
from datetime import datetime, timedelta
from typing import List

import time

from .base import BaseCollector


class NvdCpeCollector(BaseCollector):
    """通过关键词或 CPE 检索相关 CVE。"""

    source_type = "nvd_cpe"
    API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    DAYS = 7  # 拉取最近 N 天(可配置)

    # NVD 官方要求无 API key 时至少 6 秒间隔,否则返回 429
    REQUEST_INTERVAL = 6.0

    def _throttle(self, url):
        """NVD 专用限速:至少 6 秒间隔。"""
        from .. import config
        from .base import _rate_lock, _last_request_ts
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        with _rate_lock:
            now = time.monotonic()
            last = _last_request_ts.get(host, 0.0)
            wait = self.REQUEST_INTERVAL - (now - last)
            if wait > 0:
                time.sleep(wait)
            _last_request_ts[host] = time.monotonic()

    def _http_get(self, url, **kwargs):
        self._throttle(url)
        return super()._http_get(url, **kwargs)

    def collect(self) -> List[dict]:
        return self._fetch()

    def _fetch(self) -> List[dict]:
        keyword = self.source.keyword or self.source.name
        cpe = self.source.cpe

        end = datetime.utcnow()
        start = end - timedelta(days=self.DAYS)

        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 100,
            "startIndex": 0,
        }
        # 优先用 keywordSearch(支持整产品线);若配置了精确 CPE 则用 cpeName
        if keyword and not cpe:
            params["keywordSearch"] = keyword
        elif cpe:
            params["cpeName"] = cpe

        results = []
        while True:
            resp = self._http_get(self.API, params=params)
            if resp.status_code != 200:
                break
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            for v in vulns:
                results.append(self._normalize(v.get("cve", {})))
            total = data.get("totalResults", 0)
            start_index = data.get("startIndex", 0)
            per_page = data.get("resultsPerPage", 100)
            if start_index + per_page >= total:
                break
            params["startIndex"] = start_index + per_page

        return results

    def _normalize(self, cve: dict) -> dict:
        cve_id = cve.get("id", "")

        # 提取 CVSS v3.1 / v3.0 评分
        cvss = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            for m in metrics.get(key, []):
                cvss = m.get("cvssData", {}).get("baseScore")
                if cvss is not None:
                    break
            if cvss is not None:
                break

        severity = severity_from_cvss(cvss)

        desc = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                desc = d.get("value", "")
                break

        affected = set()
        for node in cve.get("configurations", []):
            for match in node.get("nodes", []):
                for cpe_match in match.get("cpeMatch", []):
                    criteria = cpe_match.get("criteria", "")
                    if criteria:
                        affected.add(criteria)

        published_at = parse_iso(cve.get("published", ""))

        return {
            "cve_id": cve_id,
            "title": f"{cve_id}: {desc[:200]}" if desc else cve_id,
            "description": desc,
            "severity": severity,
            "cvss_score": cvss,
            "affected": "; ".join(sorted(affected))[:2000] or None,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else None,
            "published_at": published_at,
            "is_kev": False,
        }


def severity_from_cvss(score) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def parse_iso(s: str):
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
    except (ValueError, AttributeError):
        return None
