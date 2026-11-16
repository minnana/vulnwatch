"""HTML 厂商公告页采集器:解析公告页表格(如 Synology 群晖、nginx)。"""
import re
from datetime import datetime
from typing import List
from urllib.parse import urljoin

from .base import BaseCollector
from .severity import guess_severity


class HtmlCollector(BaseCollector):
    """解析厂商安全公告 HTML 页,提取公告条目。

    通过正则匹配公告编号 + 标题 + 等级 + 链接。
    适配 Synology(SA 编号)、nginx(CVE 链接)等格式。

    注意:公告页通常无发布日期,故 published_at 留空,
    由系统的 first_seen_at(首次入库时间)来判断"是否新发现"。
    """

    source_type = "html"

    def collect(self) -> List[dict]:
        resp = self._http_get(self.source.url)
        if resp.status_code != 200:
            return []
        html = resp.text
        results = self._parse(html)
        if not results:
            raise RuntimeError("HTML 公告页未识别到任何公告，请检查源页面或解析规则")
        return results

    def _parse(self, html: str) -> List[dict]:
        results = []
        # 匹配公告编号,如 Synology-SA-26:19、VMSA-2026-0001、CVE-2026-15176
        pattern = r'(Synology-SA-\d+:\d+|VMSA-\d{4}-\d{4,5}|CVE-\d{4}-\d{4,7})'
        base = re.search(r'<base\b[^>]*href=["\']([^"\']+)', html, re.I)
        self._base_url = urljoin(self.source.url, base.group(1)) if base else self.source.url
        # Keep each table row/list item isolated. Reading 1500 characters after
        # a CVE mixed adjacent advisories and omitted nginx's preceding severity.
        blocks = re.findall(r'<(?:tr|li)\b[^>]*>.*?</(?:tr|li)>', html, re.I | re.S)
        blocks = [block for block in blocks if re.search(pattern, block)]
        if not blocks:
            blocks = [html]
        seen = set()
        for block in blocks:
            plain = re.sub(r'\s+', ' ', re.sub(r'<[^>]+>', ' ', block)).strip()
            for m in re.finditer(pattern, block):
                adv_id = m.group(1)
                if adv_id in seen:
                    continue
                seen.add(adv_id)
                title_match = re.search(r'<a\b[^>]*>([^<]*' + re.escape(adv_id) + r'[^<]*)</a>', block)
                title = title_match.group(1).strip() if title_match else ""
                if not title or title == adv_id:
                    title = re.split(r'Severity\s*:', plain, flags=re.I)[0][:180] or adv_id
                results.append({
                    "unique_key": adv_id,
                    "cve_id": adv_id if adv_id.startswith("CVE") else None,
                    "title": title,
                    "description": plain[:2000],
                    "severity": self._guess_severity(plain),
                    "cvss_score": None,
                    "affected": None,
                    "url": self._guess_link(block, m.start()),
                    "published_at": self._extract_date(plain),
                    "is_kev": False,
                })
        return results

    def _guess_link(self, html: str, pos: int) -> str:
        """从公告编号所在位置的附近找最近的 <a href>,拼成绝对地址。"""
        start = max(0, pos - 500)
        chunk = html[start:pos]
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', chunk)
        if hrefs:
            return urljoin(getattr(self, "_base_url", self.source.url), hrefs[-1])
        return (getattr(self.source, "url", "") or "")[:2000]

    @staticmethod
    def _extract_date(text: str):
        """尝试提取日期,如 2026-11-01 / 2026-11-1。"""
        m = re.search(r'(20\d{2})[-/](\d{1,2})[-/](\d{1,2})', text)
        if not m:
            return None
        try:
            return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)))
        except ValueError:
            return None

    @staticmethod
    def _guess_severity(text: str) -> str:
        return guess_severity(text)
