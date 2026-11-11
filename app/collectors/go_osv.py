"""Go 官方漏洞数据库(OSV 格式)采集器。"""
from datetime import datetime, timedelta
from typing import List

from .base import BaseCollector


class GoOsvCollector(BaseCollector):
    """拉取 Go 官方漏洞库(https://vuln.go.dev)的漏洞索引,OSV 格式。

    只关注 Go 标准库(stdlib)和工具链(toolchain)的漏洞,且仅拉取最近修改的条目。
    """

    source_type = "go_osv"
    BASE = "https://vuln.go.dev"
    INDEX_URL = f"{BASE}/index/vulns.json"
    DAYS = 30          # 拉最近 N 天修改的漏洞(标准库漏洞稀少,放宽窗口以捕捉)
    MAX_DETAIL = 60    # 单次最多拉取详情条数(避免全量)

    def collect(self) -> List[dict]:
        resp = self._http_get(self.INDEX_URL)
        if resp.status_code != 200:
            return []
        vulns = resp.json()
        cutoff = datetime.utcnow() - timedelta(days=self.DAYS)

        # 先按「最近修改时间」筛选候选(索引不含包名,需拉详情后才能判断归属)
        recent = []
        for v in vulns:
            vid = v.get("id", "")
            modified = self._parse(v.get("modified", ""))
            if modified and modified < cutoff:
                continue
            recent.append(vid)

        # 限制候选数量,按索引顺序(已按修改时间倒序)取前 MAX_DETAIL
        recent = recent[: self.MAX_DETAIL]

        results = []
        for vid in recent:
            detail = self._fetch_detail(vid)
            if detail:
                results.append(detail)
        return results

    def _fetch_detail(self, vid: str) -> dict:
        """拉取单个漏洞详情(OSV 格式),仅保留标准库(stdlib)/工具链(toolchain)漏洞。"""
        url = f"{self.BASE}/ID/{vid}.json"
        try:
            resp = self._http_get(url)
            if resp.status_code != 200:
                return None
            data = resp.json()

            # 仅关注 Go 标准库 / 工具链(package name 为 stdlib / toolchain)
            packages = {a.get("package", {}).get("name", "") for a in data.get("affected", [])}
            if not (packages & {"stdlib", "toolchain"}):
                return None

            summary = data.get("summary", "") or data.get("details", "")
            aliases = data.get("aliases", [])
            cve_id = next((a for a in aliases if a.startswith("CVE")), None)
            published = data.get("published", "")
            return {
                "cve_id": cve_id,
                "unique_key": vid,
                "title": f"{vid}: {summary[:150]}" if summary else vid,
                "description": summary[:2000],
                "severity": self._guess_severity(summary),
                "cvss_score": None,
                "affected": "; ".join(sorted(packages))[:1000] or "Go stdlib/toolchain",
                "url": f"https://pkg.go.dev/vuln/{vid}",
                "published_at": self._parse(published) or self._parse(data.get("modified", "")),
                "is_kev": False,
            }
        except Exception:
            return None

    @staticmethod
    def _guess_severity(text: str) -> str:
        t = (text or "").upper()
        if any(w in t for w in ("CRITICAL", "RCE", "REMOTE CODE", "CODE EXECUTION")):
            return "CRITICAL"
        if any(w in t for w in ("HIGH", "PRIVILEGE", "MEMORY CORRUPTION")):
            return "HIGH"
        if any(w in t for w in ("MEDIUM", "MODERATE", "DENIAL OF SERVICE", "DOS")):
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _parse(s: str):
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00")).replace(tzinfo=None)
        except (ValueError, AttributeError):
            return None
