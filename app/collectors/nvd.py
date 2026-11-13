"""NVD CVE API 2.0 采集器:按关键词搜索 + 日期范围拉取。

优化说明(相对原实现):
1. 原实现同一套 throttle 被叠加两次(NvdCpeCollector._http_get 调一次,再调
   BaseCollector._http_get 又调一次),实际请求间隔约 12 秒;现在只保留一次,
   由 request_interval 控制。
2. 多个 NVD 源不再各自翻页重复拉取:一轮采集内共享「最近 N 天全量 CVE」缓存,
   内存里按关键词过滤(请求数从 源数×页数 降为 页数),并带 TTL 供多轮复用。
3. 批量模式失败时自动回退为按关键词单源查询,保证可用性。

说明:NVD 的 cpeName 参数不接受通配版本号(用 `*` 会 404),
因此监控"整个产品线"时改用 keywordSearch(按产品名关键词搜索)。
如需精确到某版本,可在 URL 上使用 cpeName=...:版本号。
"""
import logging
import threading
import time
from datetime import datetime, timedelta
from typing import List, Optional

from .. import config
from .base import BaseCollector

log = logging.getLogger(__name__)

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# 进程内共享缓存:{rows: [(归一化 dict, 检索用 haystack)], expires: monotonic 秒}
_bulk_state = {"rows": None, "expires": 0.0, "error_until": 0.0}
_bulk_lock = threading.Lock()


class NvdCpeCollector(BaseCollector):
    """通过关键词或 CPE 检索相关 CVE。"""

    source_type = "nvd_cpe"
    API = API
    DAYS = config.NVD_DAYS  # 拉取最近 N 天(可配置)
    # NVD 官方要求无 API key 时至少 6 秒间隔,否则返回 429
    request_interval = config.NVD_REQUEST_INTERVAL

    def collect(self) -> List[dict]:
        # 配置了精确 CPE 的源单独查询(批量全量里拿不到精确版本信息)
        if self.source.cpe:
            return self._fetch_by_cpe(self.source.cpe)

        if not config.NVD_BULK_ENABLED:
            # 关闭批量模式时退化为按关键词查询(单个源一次请求)
            return self._fetch_by_keyword(self.source.keyword or self.source.name)

        rows = self._bulk_recent()
        keyword = (self.source.keyword or "").lower().strip()
        if rows is None:
            # 批量模式不可用:回退到单源关键词查询
            return self._fetch_by_keyword(self.source.keyword or self.source.name)
        if not keyword:
            return [item for item, _ in rows]
        return [item for item, haystack in rows if keyword in haystack]

    # ---------- 批量模式:最近 N 天全量 ----------

    def _bulk_recent(self) -> Optional[List[tuple]]:
        """返回共享缓存;失败返回 None(由调用方回退)。"""
        now = time.monotonic()
        with _bulk_lock:
            cached = _bulk_state["rows"]
            if cached is not None and now < _bulk_state["expires"]:
                return cached
            if now < _bulk_state["error_until"]:
                return None
            try:
                rows = self._fetch_range()
            except Exception as e:  # 网络/解析异常:熔断 120 秒后重试
                log.warning("NVD 批量拉取失败,回退到按关键词查询: %s", e)
                _bulk_state["error_until"] = time.monotonic() + 120
                return None
            _bulk_state["rows"] = rows
            _bulk_state["expires"] = time.monotonic() + config.NVD_CACHE_TTL
            log.info("NVD 批量拉取完成: %d 条(缓存 %d 秒)", len(rows), config.NVD_CACHE_TTL)
            return rows

    def _fetch_range(self) -> List[tuple]:
        """分页拉取最近 DAYS 天的全部 CVE(最多 MAX_PAGES 页)。"""
        end = config.utcnow()
        start = end - timedelta(days=self.DAYS)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": config.NVD_PAGE_SIZE,
            "startIndex": 0,
        }
        rows: List[tuple] = []
        for _ in range(config.NVD_MAX_PAGES):
            data = self._get_json(params)
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                item = self._normalize(v.get("cve", {}))
                haystack = " ".join(
                    str(x or "") for x in (
                        item.get("cve_id"), item.get("title"),
                        item.get("description"), item.get("affected"),
                    )
                ).lower()
                rows.append((item, haystack))
            total = int(data.get("totalResults", 0) or 0)
            start_index = int(data.get("startIndex", 0) or 0)
            per_page = int(data.get("resultsPerPage", config.NVD_PAGE_SIZE) or config.NVD_PAGE_SIZE)
            if not vulns or start_index + per_page >= total or len(rows) >= total:
                break
            params["startIndex"] = start_index + per_page
        return rows

    def _get_json(self, params: dict) -> dict:
        resp = self._http_get(self.API, params=params)
        if resp.status_code != 200:
            raise RuntimeError(f"NVD API 返回 {resp.status_code}")
        return resp.json()

    # ---------- 单源模式(回退 / 精确 CPE) ----------

    def _fetch_by_keyword(self, keyword: str) -> List[dict]:
        end = config.utcnow()
        start = end - timedelta(days=self.DAYS)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 200,
            "startIndex": 0,
            "keywordSearch": keyword,
        }
        return self._paginate(params)

    def _fetch_by_cpe(self, cpe: str) -> List[dict]:
        end = config.utcnow()
        start = end - timedelta(days=self.DAYS)
        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 200,
            "startIndex": 0,
            "cpeName": cpe,
        }
        return self._paginate(params)

    def _paginate(self, params: dict) -> List[dict]:
        results: List[dict] = []
        for _ in range(config.NVD_MAX_PAGES):
            try:
                data = self._get_json(params)
            except RuntimeError as e:
                log.warning("NVD 查询失败: %s", e)
                break
            vulns = data.get("vulnerabilities", [])
            if not vulns:
                break
            for v in vulns:
                results.append(self._normalize(v.get("cve", {})))
            total = int(data.get("totalResults", 0) or 0)
            start_index = int(data.get("startIndex", 0) or 0)
            per_page = int(data.get("resultsPerPage", 0) or 0)
            if start_index + per_page >= total:
                break
            params["startIndex"] = start_index + per_page
        return results

    # ---------- 归一化 ----------

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
