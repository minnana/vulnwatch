"""阿里云漏洞库采集器(https://avd.aliyun.com/high-risk/list)。

注意:该站点有阿里云盾 JS Challenge 反爬,普通 requests 会返回混淆 JS 而非数据。
采集器会先尝试 requests,失败则降级为 Playwright(headless 浏览器)。
若需启用此源,请安装: pip install playwright && playwright install chromium

过滤条件:等级为高危或严重。
"""
import re
from datetime import datetime
from typing import List

from .base import BaseCollector

LIST_URL = "https://avd.aliyun.com/high-risk/list"


class AvdCollector(BaseCollector):
    source_type = "avd"

    def collect(self) -> List[dict]:
        html = self._fetch_list()
        if not html:
            return []
        # 提取详情链接(列表页每条漏洞一个链接)
        links = re.findall(r'href="([^"]*avd\.aliyun\.com/detail\?id=[^"]+)"', html)
        if not links:
            links = re.findall(r'href="([^"]*detail\?id=[^"]+)"', html)
        results = []
        seen = set()
        for link in links:
            if link in seen:
                continue
            seen.add(link)
            detail = self._parse_detail(link)
            if detail:
                results.append(detail)
            if len(results) >= 30:
                break
        return results

    def _fetch_list(self) -> str:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36",
        }
        try:
            resp = self._http_get(LIST_URL, headers=headers)
            # 判断是否被 WAF 拦截(返回的是 JS 而非数据)
            if resp.status_code == 200 and "<script>function M()" not in resp.text and "tbody" in resp.text:
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
                page.wait_for_timeout(5000)
                html = page.content()
                browser.close()
                return html
        except Exception:
            return ""

    def _parse_detail(self, url: str) -> dict:
        if not url.startswith("http"):
            url = f"https://avd.aliyun.com{url}"
        try:
            resp = self._http_get(url)
        except Exception:
            return None
        if resp.status_code != 200:
            return None
        html = resp.text

        # 提取 AVD 编号
        avd_m = re.search(r"[?&]id=([A-Za-z0-9-]+)", url)
        avd_id = avd_m.group(1) if avd_m else None

        # 等级 badge
        level_m = re.search(r'class="[^"]*badge[^"]*"[^>]*>\s*([^<]+)\s*<', html)
        level = level_m.group(1).strip() if level_m else ""
        severity_map = {"低危": "LOW", "中危": "MEDIUM", "高危": "HIGH", "严重": "CRITICAL"}
        severity = severity_map.get(level, "UNKNOWN")

        # 过滤:仅高危/严重
        if severity not in ("HIGH", "CRITICAL"):
            return None

        # 标题
        title_m = re.search(r'class="[^"]*header__title__text[^"]*"[^>]*>([^<]+)<', html)
        title = title_m.group(1).strip() if title_m else (avd_id or "阿里云漏洞")

        # CVE
        cve_m = re.search(r"CVE-\d{4}-\d{4,7}", html)
        cve_id = cve_m.group(0) if cve_m else None

        return {
            "cve_id": cve_id,
            "unique_key": avd_id or cve_id,
            "title": title,
            "description": None,
            "severity": severity,
            "cvss_score": None,
            "affected": None,
            "tags": "阿里云AVD",
            "url": url,
            "published_at": None,
            "is_kev": False,
        }
