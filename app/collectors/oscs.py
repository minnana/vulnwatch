"""OSCS 开源安全情报预警采集器(https://www.oscs1024.com/cm)。

参考 watchvuln 实现:走 API 接口,过滤条件为「高危/严重 且 包含『发布预警』标签」。
优化:用列表页的 level + is_push 字段做预过滤,仅对命中「预警」的条目拉详情,减少请求。
"""
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import List

from .base import BaseCollector

LIST_API = "https://www.oscs1024.com/oscs/v1/intelligence/list"
INFO_API = "https://www.oscs1024.com/oscs/v1/vdb/info"

# 列表页 level 是中文,映射到系统等级
LEVEL_MAP = {"严重": "CRITICAL", "高危": "HIGH", "中危": "MEDIUM", "低危": "LOW"}

# 详情并发拉取度(详情接口无状态,小并发可把几十秒降到几秒;过高可能触发限流)
DETAIL_CONCURRENCY = 8


class OscsCollector(BaseCollector):
    source_type = "oscs"

    def collect(self) -> List[dict]:
        headers = {
            "Referer": "https://www.oscs1024.com/cm",
            "Origin": "https://www.oscs1024.com",
            "Content-Type": "application/json",
        }
        # 先收集所有命中的列表条目(仅按 level 预过滤),再并发拉详情
        candidates = []
        for page in range(1, 4):
            body = json.dumps({"page": page, "per_page": 20})
            try:
                resp = self._http_post(LIST_API, data=body, headers=headers)
            except Exception:
                break
            if resp is None or resp.status_code != 200:
                break
            data = resp.json()
            if data.get("code") != 200 or not data.get("success"):
                break
            items = data.get("data", {}).get("data", [])
            if not items:
                break
            for item in items:
                if LEVEL_MAP.get(item.get("level", "")) in ("HIGH", "CRITICAL"):
                    candidates.append(item)

        # 并发拉详情,保持列表顺序
        detail_map = {}
        with ThreadPoolExecutor(max_workers=DETAIL_CONCURRENCY) as pool:
            futures = {pool.submit(self._fetch_detail, it.get("mps"), headers): it for it in candidates}
            for fut in as_completed(futures):
                item = futures[fut]
                try:
                    detail_map[item.get("mps")] = fut.result()
                except Exception:
                    detail_map[item.get("mps")] = None

        results = []
        for item in candidates:
            info = self._normalize(item, headers, detail_map.get(item.get("mps")))
            if info:
                results.append(info)
        return results

    def _normalize(self, item: dict, headers: dict, detail: dict = None) -> dict:
        tags = []
        if item.get("is_push") == 1:
            tags.append("发布预警")
        intel_type = item.get("intelligence_type")
        if intel_type == 1:
            tags.append("公开漏洞")
        elif intel_type == 2:
            tags.append("墨菲安全独家")
        elif intel_type == 3:
            tags.append("投毒情报")

        mps = item.get("mps")
        if detail is None:
            detail = self._fetch_detail(mps, headers)

        severity = LEVEL_MAP.get(item.get("level"), "UNKNOWN")
        title = item.get("title")
        description = None
        cve_id = None
        cvss = None
        published = None
        affected = None

        if detail:
            cve_id = detail.get("cve_id")
            title = detail.get("title") or title
            description = detail.get("description")
            # 详情接口对未知等级会返回 "UNKNOWN"(非空),不能直接覆盖列表页已判定的
            # HIGH/CRITICAL,否则这些条目会在下面的过滤里被丢弃。
            detail_severity = detail.get("severity")
            if detail_severity in ("HIGH", "CRITICAL"):
                severity = detail_severity
            cvss = detail.get("cvss_score")
            published = detail.get("published_at")
            affected = detail.get("affected")

        # 最终过滤:高危/严重
        if severity not in ("HIGH", "CRITICAL"):
            return None

        return {
            "cve_id": cve_id,
            "unique_key": mps,
            "title": title or mps,
            "description": description,
            "severity": severity,
            "cvss_score": cvss,
            "affected": affected,
            "tags": ",".join(tags),
            "url": f"https://www.oscs1024.com/hd/{mps}",
            "published_at": published,
            "is_kev": False,
        }

    def _fetch_detail(self, mps: str, headers: dict) -> dict:
        if not mps:
            return None
        body = json.dumps({"vuln_no": mps})
        # 并发场景下直接请求,不经过同域名限速(否则并发退化为串行);
        # 详情接口无状态、响应快,8 并发可承受。
        try:
            resp = self._http_post(INFO_API, data=body, headers=headers, _skip_throttle=True)
        except Exception:
            return None
        if resp is None or resp.status_code != 200:
            return None
        data = resp.json()
        if data.get("code") != 200 or not data.get("success"):
            return None
        items = data.get("data", [])
        if not items:
            return None
        d = items[0]
        level_map = {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW"}
        severity = level_map.get(d.get("level"), "UNKNOWN")

        published = None
        pub_ms = d.get("publish_time")
        if pub_ms:
            try:
                # 原实现用 fromtimestamp(本地时区)但库里统一存 UTC,
                # 在中国时区会偏移 8 小时,导致"最近 N 天"过滤漏数据,这里改为 UTC。
                published = datetime.fromtimestamp(
                    int(pub_ms) / 1000, tz=timezone.utc
                ).replace(tzinfo=None)
            except (ValueError, TypeError, OSError):
                published = None

        affected = None
        effects = d.get("effect") or []
        names = {e.get("name") for e in effects if e.get("name")}
        if names:
            affected = "; ".join(sorted(names))

        return {
            "cve_id": d.get("cve_id"),
            "title": d.get("title"),
            "description": d.get("description"),
            "severity": severity,
            "cvss_score": d.get("cvss_score"),
            "affected": affected,
            "published_at": published,
        }
