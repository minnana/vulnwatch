"""启明星辰漏洞通告采集器(https://www.venustech.com.cn/new_type/aqtg/)。

注意:该站点有反爬(WAF),普通 requests 可能返回 403。
采集器会先尝试 requests,失败则降级为 Playwright(headless 浏览器)。
若需启用此源,请安装: pip install playwright && playwright install chromium
"""
import re
from datetime import datetime
from typing import List

from .base import BaseCollector

LIST_URL = "https://www.venustech.com.cn/new_type/aqtg/"


class VenustechCollector(BaseCollector):
    source_type = "venustech"

    def collect(self) -> List[dict]:
        html = self._fetch_list()
        if not html:
            return []
        # 提取公告详情链接
        links = re.findall(r'href="(/new_type/aqtg/[^"]+\.html)"', html)
        results = []
        seen = set()
        for link in links:
            if link in seen:
                continue
            seen.add(link)
            if "index" in link or "list" in link:
                continue
            detail = self._parse_detail(f"https://www.venustech.com.cn{link}")
            if detail:
                results.append(detail)
            if len(results) >= 20:
                break
        return results

    def _fetch_list(self) -> str:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
            "Referer": "https://www.venustech.com.cn/",
        }
        try:
            resp = self._http_get(LIST_URL, headers=headers)
            if resp.status_code == 200 and "漏洞" in resp.text:
                return resp.text
        except Exception:
            pass
        # 降级 Playwright
        return self._fetch_playwright()

    def _fetch_playwright(self) -> str:
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return ""
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36")
                page.goto(LIST_URL, timeout=30000)
                page.wait_for_timeout(3000)
                html = page.content()
                browser.close()
                return html
        except Exception:
            return ""

    def _parse_detail(self, url: str) -> dict:
        try:
            resp = self._http_get(url)
        except Exception:
            return None
        if resp.status_code != 200:
            return None
        html = resp.text

        # 表格提取:漏洞名称 / CVEID / 发现时间 / 等级
        title = self._cell(html, "漏洞名称")
        cve_raw = self._cell(html, "CVEID")
        disclosure = self._cell(html, "发现时间")
        level = self._cell(html, "漏洞等级") or self._cell(html, "等级")

        severity_map = {"严重": "CRITICAL", "紧急": "CRITICAL", "高危": "HIGH", "中危": "MEDIUM", "低危": "LOW"}
        severity = severity_map.get(level, "UNKNOWN")

        # 过滤:仅高危/严重
        if severity not in ("HIGH", "CRITICAL"):
            return None

        cve_id = None
        cve_list = re.findall(r"CVE-\d{4}-\d{4,7}", cve_raw or "")
        if cve_list:
            cve_id = cve_list[0]

        published = None
        if disclosure:
            try:
                published = datetime.strptime(disclosure.strip(), "%Y-%m-%d")
            except ValueError:
                published = None

        # 标题:去除前缀
        if title:
            title = re.sub(r"^【漏洞通告】", "", title.strip())

        return {
            "cve_id": cve_id,
            "unique_key": re.search(r"([^/]+)\.html$", url).group(1) if re.search(r"([^/]+)\.html$", url) else url,
            "title": title or "启明星辰漏洞通告",
            "description": None,
            "severity": severity,
            "cvss_score": None,
            "affected": None,
            "tags": "启明星辰",
            "url": url,
            "published_at": published,
            "is_kev": False,
        }

    @staticmethod
    def _cell(html: str, key: str) -> str:
        # 匹配 <td>key</td><td>value</td> 结构
        m = re.search(re.escape(key) + r"[^<]*</t[dh]>\s*<t[dh][^>]*>([^<]+)</t[dh]>", html)
        return m.group(1).strip() if m else ""


def _normalize_kev(data: dict) -> dict:
    """占位:保持与其它采集器一致的结构。"""
    return data
