"""HTML 厂商公告页采集器:解析公告页表格(如 Synology 群晖、nginx)。"""
import re
from datetime import datetime
from typing import List
from urllib.parse import urljoin

from .base import BaseCollector


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
        return self._parse(html)

    def _parse(self, html: str) -> List[dict]:
        results = []
        # 匹配公告编号,如 Synology-SA-26:19、VMSA-2026-0001、CVE-2026-15176
        pattern = r'(Synology-SA-\d+:\d+|VMSA-\d{4}-\d{4,5}|CVE-\d{4}-\d{4,7})'
        seen = set()
        for m in re.finditer(pattern, html):
            adv_id = m.group(1)
            if adv_id in seen:
                continue
            seen.add(adv_id)
            # 取编号后一段文本(含标签)用于提取标题与等级
            context = html[m.start(): m.start() + 1500]

            # 提取标题:编号后第一个可读文本片段
            plain = re.sub(r'<[^>]+>', ' ', context)
            plain = re.sub(r'\s+', ' ', plain).strip()
            after_id = plain[len(adv_id):].strip()
            title = after_id[:120] if after_id else adv_id

            severity = self._guess_severity(plain)

            # 尝试提取发布日期(如 Synology 的 2026-11-1 格式)
            published_at = self._extract_date(plain)

            # 提取链接:公告编号通常处在 <a href="..."> 标签内,
            # 用编号前 500 字符内最后一个 href(相对地址用 urljoin 补全)。
            link = self._guess_link(html, m.start())

            results.append({
                "cve_id": adv_id if adv_id.startswith("CVE") else None,
                "title": f"{adv_id}: {title}" if not adv_id.startswith("CVE") else title,
                "description": plain[:2000],
                "severity": severity,
                "cvss_score": None,
                "affected": None,
                "url": link,
                "published_at": published_at,
                "is_kev": False,
            })
        return results

    def _guess_link(self, html: str, pos: int) -> str:
        """从公告编号所在位置的附近找最近的 <a href>,拼成绝对地址。"""
        start = max(0, pos - 500)
        chunk = html[start:pos]
        hrefs = re.findall(r'href=["\']([^"\']+)["\']', chunk)
        if hrefs:
            return urljoin(getattr(self.source, "url", "") or "", hrefs[-1])
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
        t = (text or "").upper()
        if any(w in t for w in ("CRITICAL", "严重", "RCE", "REMOTE CODE")):
            return "CRITICAL"
        if any(w in t for w in ("IMPORTANT", "高危", "HIGH")):
            return "HIGH"
        if any(w in t for w in ("MODERATE", "MEDIUM", "中危")):
            return "MEDIUM"
        if any(w in t for w in ("LOW", "低危", "NOT AFFECTED", "不受影响")):
            return "LOW"
        return "UNKNOWN"
