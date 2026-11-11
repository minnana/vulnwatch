"""通用 RSS / 厂商公告采集器。"""
import re
from datetime import datetime, timedelta
from typing import List

import feedparser

from .base import BaseCollector


class RssCollector(BaseCollector):
    """解析 RSS/Atom feed,提取公告条目。"""

    source_type = "rss"
    DAYS = 14  # 只保留最近 N 天内的条目

    def collect(self) -> List[dict]:
        resp = self._http_get(self.source.url)
        if resp.status_code != 200:
            return []
        feed = feedparser.parse(resp.content)
        keywords = [k.strip().lower() for k in (self.source.keyword or "").split(",") if k.strip()]
        cutoff = datetime.utcnow() - timedelta(days=self.DAYS)

        results = []
        for entry in feed.entries:
            title = entry.get("title", "")
            link = entry.get("link", "")
            summary = entry.get("summary", "") or entry.get("description", "")
            # 关键词过滤(若配置了关键词,标题/摘要需包含其一)
            if keywords:
                text = f"{title} {summary}".lower()
                if not any(k in text for k in keywords):
                    continue

            published_at = self._parse_date(entry)
            # 过滤过期条目
            if published_at and published_at < cutoff:
                continue

            results.append({
                "cve_id": self._extract_cve(title + " " + summary),
                "title": title,
                "description": strip_html(summary)[:2000],
                "severity": self._guess_severity(title + " " + summary),
                "cvss_score": None,
                "affected": None,
                "url": link,
                "published_at": published_at,
                "is_kev": False,
            })
        return results

    @staticmethod
    def _extract_cve(text: str) -> str:
        m = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
        return m.group(0).upper() if m else None

    @staticmethod
    def _guess_severity(text: str) -> str:
        t = text.upper()
        if any(w in t for w in ("CRITICAL", "严重", "RCE", "REMOTE CODE", "IN-THE-WILD", "在野", "ACTIVELY EXPLOITED")):
            return "CRITICAL"
        if any(w in t for w in ("HIGH", "高危", "IMPORTANT")):
            return "HIGH"
        if any(w in t for w in ("MEDIUM", "MODERATE", "中危")):
            return "MEDIUM"
        if any(w in t for w in ("LOW", "低危")):
            return "LOW"
        return "UNKNOWN"

    @staticmethod
    def _parse_date(entry):
        for field in ("published_parsed", "updated_parsed"):
            parsed = entry.get(field)
            if parsed:
                try:
                    return datetime(*parsed[:6])
                except (TypeError, ValueError):
                    continue
        return None


def strip_html(text: str) -> str:
    return re.sub(r"<[^>]+>", " ", text or "").strip()
