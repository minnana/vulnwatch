"""采集编排 + 定时任务。

优化点:
1. 多源并行采集(ThreadPoolExecutor):原实现逐个源串行,最慢的源会拖死整轮任务;
   每个工作线程使用自己的 DB Session(SQLAlchemy Session 非线程安全)。
2. 每个源采集结果批量入库(crud.upsert_many 一次 commit),不再逐条 commit。
3. 全局采集锁:定时任务与 Web 手动采集不会并发执行同一批源,避免数据竞争。
4. 首次采集「基线保护」:库里没有漏洞时只入库、不推送,避免首次上线轰炸历史数据。
5. 推送报告分片发送;静默时段/定时时间统一按业务时区(config.now_local)计算。
6. 每次任务都写 AlertLog(success/failed/skipped/silent/baseline),便于追溯。
"""
import logging
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import monotonic
from typing import Callable, List, Optional, Tuple

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from . import config, crud, models
from .collectors import get_collector
from .notifier import CHANNEL_KEYS, build_report_messages, send

logger = logging.getLogger("vulnwatch")
scheduler = BackgroundScheduler(timezone=config.TZ)

# ---------- 采集互斥 ----------

_collect_lock = threading.Lock()
_collecting = threading.Event()

DAILY_JOB_ID = "daily_vuln_job"


class CollectionBusy(RuntimeError):
    """已有采集任务正在运行。"""


def is_collecting() -> bool:
    return _collecting.is_set()


def begin_collection(blocking: bool = False) -> bool:
    """获取采集锁;成功返回 True(调用方必须配对 end_collection)。"""
    if not _collect_lock.acquire(blocking=blocking):
        return False
    _collecting.set()
    return True


def end_collection() -> None:
    _collecting.clear()
    try:
        _collect_lock.release()
    except RuntimeError:
        pass


# ---------- 采集 ----------

def collect_source(db, source: models.MonitorSource) -> dict:
    """采集单个监控源,入库,返回统计。"""
    result = {
        "source_id": source.id,
        "source_name": source.name,
        "fetched": 0,
        "new_count": 0,
        "new_vulns": [],
        "error": None,
    }
    try:
        collector = get_collector(source)
        items = collector.collect()
        result["fetched"] = len(items)
        new_count, new_items = crud.upsert_many(db, source.id, items)
        result["new_count"] = new_count
        result["new_vulns"] = new_items
    except Exception as e:
        logger.exception("采集 %s 失败", source.name)
        try:
            db.rollback()
        except Exception:
            pass
        result["error"] = str(e)
    return result


def _collect_one(source_id: int, source_name: str) -> dict:
    """工作线程入口:独立 Session 采集单个源。"""
    from .database import SessionLocal

    db = SessionLocal()
    try:
        source = crud.get_source(db, source_id)
        if source is None:
            return {
                "source_id": source_id,
                "source_name": source_name,
                "fetched": 0,
                "new_count": 0,
                "new_vulns": [],
                "error": "监控源不存在(可能已被删除)",
            }
        return collect_source(db, source)
    finally:
        db.close()


def collect_all(on_result: Optional[Callable[[dict], None]] = None) -> List[dict]:
    """并行采集所有启用的监控源。

    on_result: 每完成一个源的回调(用于 Web 端轮询展示实时进度)。
    """
    from .database import SessionLocal

    db = SessionLocal()
    try:
        sources = [(s.id, s.name) for s in crud.list_sources(db, enabled_only=True)]
    finally:
        db.close()

    if not sources:
        return []

    workers = max(1, min(config.COLLECT_MAX_WORKERS, len(sources)))
    results: List[dict] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_collect_one, sid, name): (sid, name) for sid, name in sources}
        for fut in as_completed(futures):
            sid, name = futures[fut]
            try:
                r = fut.result()
            except Exception as e:  # 理论上 collect_source 已捕获,这里兜底
                logger.exception("采集 %s 线程异常", name)
                r = {
                    "source_id": sid,
                    "source_name": name,
                    "fetched": 0,
                    "new_count": 0,
                    "new_vulns": [],
                    "error": str(e),
                }
            results.append(r)
            logger.info("采集 %s: 获取 %s 条, 新增 %s 条", name, r["fetched"], r["new_count"])
            if on_result:
                try:
                    on_result(r)
                except Exception:
                    logger.exception("采集进度回调失败")

    results.sort(key=lambda r: (r.get("source_id") or 0))
    return results


# ---------- 过滤逻辑 ----------

def _field(v, name, default=None):
    """兼容 ORM 对象与 dict 两种数据形态。"""
    if isinstance(v, dict):
        return v.get(name, default)
    return getattr(v, name, default)


def _parse_csv(value) -> List[str]:
    """把逗号分隔的配置串拆成非空词列表,统一小写。"""
    if not value:
        return []
    return [w.strip().lower() for w in str(value).split(",") if w.strip()]


def _match_keywords(v, include: List[str], exclude: List[str]) -> bool:
    """产品关键词黑白名单过滤。

    include 非空时:标题/受影响产品/CVE 需命中任一 include 词;
    exclude 非空时:命中任一 exclude 词则丢弃。
    """
    haystack = " ".join([
        str(_field(v, "title") or ""),
        str(_field(v, "affected") or ""),
        str(_field(v, "cve_id") or ""),
    ]).lower()
    if include and not any(k in haystack for k in include):
        return False
    if exclude and any(k in haystack for k in exclude):
        return False
    return True


def _match_tags(v, required_tags: List[str]) -> bool:
    """标签过滤:required_tags 非空时,漏洞 tags 需命中至少一个。"""
    if not required_tags:
        return True
    tags = _parse_csv(_field(v, "tags"))
    return any(t in tags for t in required_tags)


def parse_hhmm(value) -> Optional[Tuple[int, int]]:
    """解析 "HH:MM" 配置,非法返回 None。"""
    if not value:
        return None
    m = re.match(r"^\s*(\d{1,2})\s*[:：]\s*(\d{1,2})\s*$", str(value))
    if not m:
        return None
    hour, minute = int(m.group(1)), int(m.group(2))
    if 0 <= hour <= 23 and 0 <= minute <= 59:
        return hour, minute
    return None


def _is_silent_time(db) -> bool:
    """静默时段:配置的静默窗口内不推送(默认关闭,可配 00:00-07:00)。"""
    enabled = (crud.get_setting(db, "silent_hours_enabled", "false") or "false").lower() in (
        "true", "1", "yes",
    )
    if not enabled:
        return False
    start = parse_hhmm(crud.get_setting(db, "silent_hours_start", "00:00"))
    end = parse_hhmm(crud.get_setting(db, "silent_hours_end", "07:00"))
    if not start or not end:
        return False
    now = config.now_local().time()
    s = now.replace(hour=start[0], minute=start[1], second=0, microsecond=0)
    e = now.replace(hour=end[0], minute=end[1], second=0, microsecond=0)
    if s < e:
        return s <= now < e
    # 跨天窗口(如 22:00-06:00)
    return now >= s or now < e


def _dedup_by_cve(vulns: List) -> List:
    """跨源同一 CVE 去重:有 CVE 的按 cve_id 保留一条(在野利用 > 等级最高 > 评分最高),
    无 CVE 的(厂商公告)保留 unique_key 唯一。"""
    ordered = sorted(
        vulns,
        key=lambda v: (
            0 if _field(v, "is_kev") else 1,
            {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}.get(
                (_field(v, "severity") or "UNKNOWN").upper(), 4
            ),
            -(_field(v, "cvss_score") or 0),
        ),
    )
    seen_cve = set()
    seen_key = set()
    out = []
    for v in ordered:
        cve_id = (_field(v, "cve_id") or "").upper()
        unique_key = _field(v, "unique_key")
        if cve_id:
            if cve_id in seen_cve:
                continue
            seen_cve.add(cve_id)
            out.append(v)
        elif unique_key:
            if unique_key in seen_key:
                continue
            seen_key.add(unique_key)
            out.append(v)
        else:
            out.append(v)
    return out


def _filter_to_push(db, new_vulns: List, threshold: str) -> List:
    """完整的推送过滤流水线:等级阈值 → 产品黑白名单 → 标签 → 跨源去重。"""
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    th_rank = rank.get(threshold.upper(), 1)

    include = _parse_csv(crud.get_setting(db, "include_keywords", ""))
    exclude = _parse_csv(crud.get_setting(db, "exclude_keywords", ""))
    required_tags = _parse_csv(crud.get_setting(db, "required_tags", ""))

    result = []
    for v in new_vulns:
        # 1. 等级阈值(在野利用 KEV 强制保留)
        if not (_field(v, "is_kev") or rank.get((_field(v, "severity") or "UNKNOWN").upper(), 4) <= th_rank):
            continue
        # 2. 产品关键词黑白名单
        if not _match_keywords(v, include, exclude):
            continue
        # 3. 标签过滤
        if not _match_tags(v, required_tags):
            continue
        result.append(v)

    # 4. 跨源 CVE 去重
    return _dedup_by_cve(result)


# ---------- 每日任务 ----------

def _fill_ai_summaries(db, vulns: List) -> None:
    """给推送列表里的前 N 条补中文摘要(仅在配置了 DeepSeek Key 时)。"""
    api_key = crud.get_setting(db, "deepseek_api_key", "") or ""
    if not api_key or not vulns:
        return
    from .summarize import summarize_vuln

    mapping = {}
    for v in vulns[: max(0, config.AI_SUMMARY_LIMIT)]:
        if _field(v, "ai_summary"):
            continue
        vid = _field(v, "id")
        if not vid:
            continue
        summary = summarize_vuln(api_key, v)
        if summary:
            if isinstance(v, dict):
                v["ai_summary"] = summary
            else:
                v.ai_summary = summary
            mapping[vid] = summary
    if mapping:
        try:
            crud.update_ai_summaries(db, mapping)
        except Exception:
            logger.exception("写回 AI 摘要失败")


def _log_alert(db, severity: str, count: int, status: str, detail: str) -> None:
    try:
        db.add(models.AlertLog(severity=severity, count=count, status=status, detail=detail))
        db.commit()
    except Exception:
        logger.exception("写推送日志失败")
        try:
            db.rollback()
        except Exception:
            pass


def run_daily_job():
    """每日汇总任务:采集 → 过滤 → 推送 → 记录日志。

    只推送「本次采集新增」的漏洞(而非近 24 小时全量),这样首次建基线不会
    轰炸历史数据,后续也只推真实增量。
    """
    from .database import SessionLocal

    if not begin_collection(blocking=False):
        logger.warning("每日任务跳过:已有采集任务在运行")
        return
    db = SessionLocal()
    try:
        baseline = crud.count_vulnerabilities(db) == 0
        total_new = 0
        to_push: List = []
        threshold = (crud.get_setting(db, "alert_threshold", "HIGH") or "HIGH").upper()

        results = collect_all()
        total_new = sum(r["new_count"] for r in results)
        new_vulns: List = []
        for r in results:
            new_vulns.extend(r.get("new_vulns", []))

        if baseline:
            detail = f"首次采集建立基线:新增 {total_new} 条,本次不推送"
            _log_alert(db, threshold, 0, "baseline", detail)
            logger.info("每日任务:%s", detail)
            return

        to_push = _filter_to_push(db, new_vulns, threshold)
        detail = f"新增 {total_new} 条,过滤后 {len(to_push)} 条"

        # 静默时段:静默窗口内只入库不推送
        if _is_silent_time(db):
            _log_alert(db, threshold, 0, "silent", detail + ",静默时段不推送")
            logger.info("每日任务:静默时段,跳过推送(%s 新增)", total_new)
            return

        # 通道路由:读 notify_channel,默认钉钉;未知通道回退钉钉
        channel = (crud.get_setting(db, "notify_channel", "dingtalk") or "dingtalk").strip().lower()
        if channel not in CHANNEL_KEYS:
            logger.warning("未知通知通道 %s,回退 dingtalk", channel)
            channel = "dingtalk"
        cred_key, secret_key = CHANNEL_KEYS[channel]
        credential = crud.get_setting(db, cred_key, "") or ""
        secret = (crud.get_setting(db, secret_key, "") or "") if secret_key else ""

        if not to_push or not credential:
            _log_alert(db, threshold, 0, "skipped", detail + ",无需要推送内容或未配置凭证")
            logger.info("每日任务:跳过推送(%s)", detail)
            return

        # AI 摘要(可选增强,失败不影响主链路)
        _fill_ai_summaries(db, to_push)

        messages = build_report_messages(to_push, threshold)
        ok = True
        for idx, text in enumerate(messages, 1):
            if not send(channel, credential, secret, "漏洞情报汇总", text):
                ok = False
                logger.warning("第 %d/%d 段报告发送失败", idx, len(messages))
        status = "success" if ok else "failed"
        detail += f",推送 {len(to_push)} 条/{len(messages)} 条消息(通道:{channel})"
        _log_alert(db, threshold, len(to_push), status, detail)
        logger.info("每日任务完成: 新增 %s, 过滤后 %s, 推送 %s 条 [%s]",
                    total_new, len(to_push), len(to_push), status)
    except Exception as e:
        logger.exception("每日任务异常")
        _log_alert(db, "UNKNOWN", 0, "failed", f"任务异常: {e}")
    finally:
        db.close()
        end_collection()


# ---------- 定时器 ----------

def _configured_daily_time(db=None) -> Tuple[int, int]:
    """优先读 Web 配置 daily_time(HH:MM),否则用环境变量默认值。"""
    hour, minute = config.DAILY_HOUR, config.DAILY_MINUTE
    own = False
    if db is None:
        from .database import SessionLocal
        db = SessionLocal()
        own = True
    try:
        parsed = parse_hhmm(crud.get_setting(db, "daily_time", ""))
        if parsed:
            hour, minute = parsed
    finally:
        if own:
            db.close()
    return hour, minute


def _daily_trigger(hour: int, minute: int) -> CronTrigger:
    return CronTrigger(hour=hour, minute=minute, timezone=config.TZ)


def start_scheduler(db=None):
    """启动定时任务(服务启动时调用一次)。"""
    if scheduler.running:
        return
    hour, minute = _configured_daily_time(db)
    scheduler.add_job(
        run_daily_job,
        _daily_trigger(hour, minute),
        id=DAILY_JOB_ID,
        replace_existing=True,
        max_instances=1,
        coalesce=True,
        misfire_grace_time=3600,
    )
    scheduler.start()
    logger.info("定时任务已启动: 每日 %02d:%02d (%s)", hour, minute, config.TIMEZONE_NAME)


def reschedule_daily_job(db=None) -> Tuple[int, int]:
    """Web 修改 daily_time 后立即生效。返回新的 (hour, minute)。"""
    hour, minute = _configured_daily_time(db)
    if scheduler.running and scheduler.get_job(DAILY_JOB_ID):
        scheduler.reschedule_job(DAILY_JOB_ID, trigger=_daily_trigger(hour, minute))
        logger.info("定时任务已重排: 每日 %02d:%02d", hour, minute)
    return hour, minute


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("定时任务已停止")


def collect_elapsed(started_at: float) -> float:
    """辅助:返回本次采集已耗时(秒),供状态接口展示。"""
    return round(monotonic() - started_at, 1)
