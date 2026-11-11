"""采集器基类与注册表。"""
import os
import threading
import time
from urllib.parse import urlparse

import requests

from .. import config

HEADERS = {
    "User-Agent": "VulnWatch/0.1 (security monitoring)",
    "Accept": "application/json, application/xml, text/xml, */*",
}

# 按域名记录上次请求时间,实现「同一域名内请求间隔」限速。
# 好处:单源内多次请求(拉详情)不再每次都 sleep 一个长间隔,
# 而是保证同一域名两次请求之间至少间隔 REQUEST_INTERVAL 秒,
# 跨域名请求互不影响,整体采集速度大幅提升且仍不触发目标限流。
_rate_lock = threading.Lock()
_last_request_ts: dict[str, float] = {}


def _throttle(url: str):
    """对同一域名做最小请求间隔限速。"""
    host = urlparse(url).netloc
    interval = config.REQUEST_INTERVAL
    if interval <= 0:
        return
    with _rate_lock:
        now = time.monotonic()
        last = _last_request_ts.get(host, 0.0)
        wait = interval - (now - last)
        if wait > 0:
            time.sleep(wait)
        _last_request_ts[host] = time.monotonic()


# 网络抖动重试次数(超时/连接错误自动重试,避免单个源因偶发超时整源失败)
RETRY_TIMES = int(os.getenv("VULNWATCH_RETRY_TIMES", "2"))


class BaseCollector:
    """所有采集器的基类。"""

    source_type = "base"

    def __init__(self, source):
        self.source = source

    def _http_get(self, url, **kwargs):
        """带限速、重试和超时的 HTTP GET,返回 Response。"""
        _throttle(url)
        headers = {**HEADERS, **kwargs.pop("headers", {})}
        last_exc = None
        for attempt in range(RETRY_TIMES + 1):
            try:
                return requests.get(
                    url,
                    headers=headers,
                    timeout=config.REQUEST_TIMEOUT,
                    **kwargs,
                )
            except requests.exceptions.RequestException as e:
                last_exc = e
                if attempt < RETRY_TIMES:
                    time.sleep(1 + attempt)
        raise last_exc

    def _http_post(self, url, **kwargs):
        """带限速、重试和超时的 HTTP POST,返回 Response。

        传 _skip_throttle=True 可跳过限速(用于采集器内部的并发批量请求)。
        """
        if not kwargs.pop("_skip_throttle", False):
            _throttle(url)
        headers = {**HEADERS, **kwargs.pop("headers", {})}
        last_exc = None
        for attempt in range(RETRY_TIMES + 1):
            try:
                return requests.post(
                    url,
                    headers=headers,
                    timeout=config.REQUEST_TIMEOUT,
                    **kwargs,
                )
            except requests.exceptions.RequestException as e:
                last_exc = e
                if attempt < RETRY_TIMES:
                    time.sleep(1 + attempt)
        raise last_exc

    def collect(self):
        """返回归一化后的漏洞 dict 列表。子类必须实现。"""
        raise NotImplementedError


def get_collector(source):
    """根据 source_type 返回对应采集器实例。"""
    from . import avd, chaitin, cisa_kev, go_osv, html, nvd, oscs, qianxin_ti, rss, seebug, struts2, threatbook, venustech

    mapping = {
        "nvd_cpe": nvd.NvdCpeCollector,
        "cisa_kev": cisa_kev.CisaKevCollector,
        "rss": rss.RssCollector,
        "html": html.HtmlCollector,
        "go_osv": go_osv.GoOsvCollector,
        # 国内漏洞源(参考 watchvuln)
        "chaitin": chaitin.ChaitinCollector,
        "oscs": oscs.OscsCollector,
        "qianxin_ti": qianxin_ti.QianxinTiCollector,
        "threatbook": threatbook.ThreatbookCollector,
        "seebug": seebug.SeebugCollector,
        "struts2": struts2.Struts2Collector,
        "avd": avd.AvdCollector,
        "venustech": venustech.VenustechCollector,
    }
    cls = mapping.get(source.source_type)
    if not cls:
        raise ValueError(f"未知采集器类型: {source.source_type}")
    return cls(source)
