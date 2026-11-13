"""采集器基类与注册表。"""
import logging
import threading
import time
from typing import Optional
from urllib.parse import urlparse

import requests

from .. import config

log = logging.getLogger(__name__)

HEADERS = {
    "User-Agent": "VulnWatch/0.1 (security monitoring)",
    "Accept": "application/json, application/xml, text/xml, */*",
}

# 按域名记录「下一个可用请求时间」,实现「同一域名内请求间隔」限速。
# 注意:先在锁内预约时间槽、再在锁外 sleep —— 否则 sleep 期间会持有全局锁,
# 导致所有域名、所有采集线程被串行化(原实现在 _rate_lock 内 sleep 的问题)。
_rate_lock = threading.Lock()
_last_request_ts: dict = {}

# 网络抖动重试次数(超时/连接错误自动重试,避免单个源因偶发超时整源失败)
RETRY_TIMES = config.RETRY_TIMES

# 每个线程一个 requests.Session:复用 TCP 连接,批量请求时明显更快
_thread_local = threading.local()


def get_session() -> requests.Session:
    """返回当前线程的 requests.Session(自动带上默认 UA/Accept)。"""
    sess = getattr(_thread_local, "session", None)
    if sess is None:
        sess = requests.Session()
        sess.headers.update(HEADERS)
        _thread_local.session = sess
    return sess


def _throttle(url: str, interval: Optional[float] = None):
    """对同一域名做最小请求间隔限速。

    预约式实现:锁内计算并写入「下一次可请求时间」,锁外 sleep 到该时刻。
    这样等待期间不会阻塞其他线程/其他域名的请求。
    """
    if interval is None:
        interval = config.REQUEST_INTERVAL
    if interval <= 0:
        return
    host = urlparse(url).netloc
    with _rate_lock:
        now = time.monotonic()
        last = _last_request_ts.get(host, 0.0)
        slot = max(now, last + interval)
        _last_request_ts[host] = slot
    delay = slot - now
    if delay > 0:
        time.sleep(delay)


class BaseCollector:
    """所有采集器的基类。"""

    source_type = "base"
    # 子类可覆盖:该源专用的请求间隔(秒),None 表示用全局 config.REQUEST_INTERVAL
    request_interval: Optional[float] = None

    def __init__(self, source):
        self.source = source

    def _request(self, method: str, url: str, **kwargs):
        """带限速、重试和超时的 HTTP 请求,返回 Response。

        传 _skip_throttle=True 可跳过限速(用于采集器内部的并发批量请求)。
        """
        if not kwargs.pop("_skip_throttle", False):
            self._throttle(url)
        headers = {**HEADERS, **kwargs.pop("headers", {})}
        last_exc = None
        for attempt in range(RETRY_TIMES + 1):
            try:
                return get_session().request(
                    method, url, headers=headers, timeout=config.REQUEST_TIMEOUT, **kwargs
                )
            except requests.exceptions.RequestException as e:
                last_exc = e
                if attempt < RETRY_TIMES:
                    log.warning("请求失败(第 %d 次重试前) %s %s: %s", attempt + 1, method, url, e)
                    time.sleep(1 + attempt)
        if last_exc is not None:
            raise last_exc
        raise RuntimeError(f"请求未执行(重试次数配置异常): {method} {url}")

    def _throttle(self, url: str):
        _throttle(url, self.request_interval)

    def _http_get(self, url, **kwargs):
        """带限速、重试和超时的 HTTP GET,返回 Response。"""
        return self._request("GET", url, **kwargs)

    def _http_post(self, url, **kwargs):
        """带限速、重试和超时的 HTTP POST,返回 Response。

        传 _skip_throttle=True 可跳过限速(用于采集器内部的并发批量请求)。
        """
        return self._request("POST", url, **kwargs)

    def collect(self):
        """返回归一化后的漏洞 dict 列表。子类必须实现。"""
        raise NotImplementedError


def get_collector(source):
    """根据 source_type 返回对应采集器实例。"""
    from . import (
        avd, chaitin, cisa_kev, go_osv, html, nvd, oscs, qianxin_ti, rss,
        seebug, struts2, threatbook, venustech,
    )

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
