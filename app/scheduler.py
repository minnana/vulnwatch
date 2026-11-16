"""采集编排 + 定时任务。

优化点:
1. 多源并行采集(ThreadPoolExecutor):原实现逐个源串行,最慢的源会拖死整轮任务;
   每个工作线程使用自己的 DB Session(SQLAlchemy Session 非线程安全)。
2. 每个源采集结果批量入库(crud.upsert_many 一次 commit),不再逐条 commit。
3. 全局采集锁:定时任务与 Web 手动采集不会并发执行同一批源,避免数据竞争。
4. 每个源首次成功采集建立历史基线,失败不建基线,后续待推送记录持久化。
5. 推送报告分片发送;静默时段/定时时间统一按业务时区(config.now_local)计算。
6. 每次任务都写 AlertLog(success/failed/skipped/silent/baseline),便于追溯。
"""
import logging
import re
import threading
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from time import monotonic
from typing import Callable, List, Optional, Tuple

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger

from . import config, crud, models
from .collectors import get_collector
from .notifier import CHANNEL_KEYS, build_report_batches, send

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
        result["baseline"] = crud.record_collection(db, source.id, len(items), new_count)
    except Exception as e:
        logger.exception("采集 %s 失败", source.name)
        try:
            db.rollback()
        except Exception:
            pass
        result["error"] = str(e)
        try:
            crud.record_collection(db, source.id, 0, 0, str(e))
        except Exception:
            db.rollback()
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

    from .collectors.nvd import invalidate_bulk_cache
    invalidate_bulk_cache()
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
        cve_id = (_field(v, "cve_id") or "").strip().upper()
        unique_key = (_field(v, "source_id"), _field(v, "unique_key")) if _field(v, "unique_key") else None
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


def _recent_discovery(v, max_age_days):
    """Compare publication with discovery, so delayed/failed alerts never age out."""
    if not max_age_days or _field(v, "is_kev"):
        return True
    published = _field(v, "published_at")
    discovered = _field(v, "first_seen_at") or config.utcnow()
    def utc(value):
        if isinstance(value, str):
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value
    try:
        return not published or utc(published) >= utc(discovered) - timedelta(days=max_age_days)
    except (ValueError, TypeError, AttributeError):
        return True


def _filter_to_push(db, new_vulns: List, threshold: str) -> List:
    """完整的推送过滤流水线:等级阈值 → 产品黑白名单 → 标签 → 跨源去重。"""
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    th_rank = rank.get(threshold.upper(), 1)

    include = _parse_csv(crud.get_setting(db, "include_keywords", ""))
    exclude = _parse_csv(crud.get_setting(db, "exclude_keywords", ""))
    required_tags = _parse_csv(crud.get_setting(db, "required_tags", ""))

    max_age_days = int(crud.get_setting(db, "alert_max_age_days", "7"))
    result = []
    for v in new_vulns:
        if not _recent_discovery(v, max_age_days):
            continue
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


# ---------- 推送：即时、每日、手动共用回执与互斥锁 ----------

_notification_lock = threading.Lock()
_last_send_at = 0.0
_retry_after = 0.0


def begin_notification() -> bool:
    return _notification_lock.acquire(blocking=False)


def end_notification() -> None:
    _notification_lock.release()


def is_notifying() -> bool:
    return _notification_lock.locked()


def setting_bool(db, key, default=False):
    return str(crud.get_setting(db, key, str(default))).lower() == "true"


def _log_alert(db, severity, count, status, detail):
    db.add(models.AlertLog(severity=severity, count=count, status=status, detail=detail))
    db.commit()


def notification_selection(db, mode="pending", ids=None):
    if mode == "selected":
        rows = db.query(models.Vulnerability).filter(models.Vulnerability.id.in_(ids or [])).all()
        if len(rows) != len(set(ids or [])):
            raise ValueError("部分所选漏洞已不存在，请刷新列表")
        return _dedup_by_cve(rows), "MANUAL"
    default = "CRITICAL" if mode == "instant" else "HIGH"
    threshold = (crud.get_setting(db, "instant_threshold" if mode == "instant" else "alert_threshold", default) or default).upper()
    return _filter_to_push(db, crud.pending_notifications(db), threshold), threshold


def channel_config(db):
    channel = crud.get_setting(db, "notify_channel", "dingtalk") or "dingtalk"
    if channel not in CHANNEL_KEYS:
        raise ValueError("通知通道无效，请检查配置")
    cred_key, secret_key = CHANNEL_KEYS[channel]
    return (channel, crud.get_setting(db, cred_key, "") or "",
            (crud.get_setting(db, secret_key, "") or "") if secret_key else "")


def notification_preview(db, mode="pending", ids=None):
    rows, threshold = notification_selection(db, mode, ids)
    channel, credential, _ = channel_config(db)
    batches = build_report_batches(rows, threshold, report_title="手动指定漏洞推送" if mode == "selected" else "手动漏洞情报推送")
    return {"mode": mode, "channel": channel, "configured": bool(credential),
            "count": len(rows), "parts": len(batches),
            "messages": [text for text, _ in batches],
            "items": [{"id": v.id, "cve": v.cve_id or v.unique_key,
                       "title": v.title, "severity": v.severity, "is_kev": v.is_kev} for v in rows],
            "note": "所选记录允许重复发送，忽略自动推送阈值和静默时段。" if mode == "selected"
                    else "发送符合过滤条件的待推送内容；已成功发送和首次历史基线不重复发送。手动操作不受静默时段限制。"}


def instant_batch_due(db, rows):
    regular = [v for v in rows if not v.is_kev and v.severity != "CRITICAL"]
    if not regular:
        return None
    minutes = int(crud.get_setting(db, "instant_batch_minutes", "5"))
    return min(v.first_seen_at or config.utcnow() for v in regular) + timedelta(minutes=minutes)


def _automatic_enabled(db, mode):
    return (setting_bool(db, "notifications_enabled", True)
            and setting_bool(db, "instant_enabled" if mode == "instant" else "daily_enabled", True))


def deliver_notifications(db, mode="instant", ids=None):
    """Caller owns the notification lock. AI calls never block this path."""
    if mode in ("instant", "daily") and not _automatic_enabled(db, mode):
        return {"status": "disabled", "sent": 0, "count": 0}
    rows, threshold = notification_selection(db, mode, ids)
    label = {"instant": "即时告警", "daily": "每日汇总",
             "pending": "手动推送", "selected": "手动指定推送"}[mode]
    original_count = len(rows)
    if mode in ("instant", "daily") and _is_silent_time(db):
        # Severe / actively exploited alerts may bypass quiet hours by explicit policy.
        rows = [v for v in rows if setting_bool(db, "urgent_bypass_silent", True)
                and (v.is_kev or v.severity == "CRITICAL")]
    buffered = False
    if mode == "instant" and rows:
        due = instant_batch_due(db, rows)
        if due and config.utcnow() < due:
            buffered = True
            rows = [v for v in rows if v.is_kev or v.severity == "CRITICAL"]
    if not rows:
        status = "buffered" if buffered else ("silent" if original_count else "skipped")
        if mode != "instant":
            _log_alert(db, threshold, 0, status, f"{label}: 待推送 {original_count} 条，当前无可发送内容")
        return {"status": status, "sent": 0, "count": original_count}
    channel, credential, secret = channel_config(db)
    if not credential:
        _log_alert(db, threshold, 0, "failed", f"{label}: 未配置 {channel} 凭证，保留待推送内容")
        return {"status": "failed", "sent": 0, "count": len(rows), "detail": "未配置通知凭证"}
    titles = {"instant": "🚨 漏洞即时告警", "daily": "每日漏洞情报汇总",
              "pending": "手动漏洞情报推送", "selected": "手动指定漏洞推送"}
    batches = build_report_batches(rows, threshold, report_title=titles[mode])
    sent_count = 0
    status = "success"
    for message, batch in batches:
        if mode in ("instant", "daily") and not _automatic_enabled(db, mode):
            status = "paused"
            break
        if not _rate_limited_send(channel, credential, secret, titles[mode], message):
            status = "failed"
            break
        crud.acknowledge_notifications(db, batch)
        sent_count += len(batch)
    detail = f"{label}: 已发送 {sent_count}/{len(rows)} 条，共 {len(batches)} 段，通道 {channel}"
    if status == "failed":
        detail += "；失败内容未确认，可重试"
    elif status == "paused":
        detail += "；自动推送已暂停，剩余内容保留"
    _log_alert(db, threshold, sent_count, status, detail)
    return {"status": status, "sent": sent_count, "count": len(rows), "parts": len(batches), "detail": detail}


def _rate_limited_send(channel, credential, secret, title, message):
    # The notification lock serializes callers; pace across sources and batches.
    global _last_send_at
    from time import sleep
    delay = 3.1 - (monotonic() - _last_send_at)
    if delay > 0:
        sleep(delay)
    try:
        return send(channel, credential, secret, title, message)
    finally:
        _last_send_at = monotonic()


def dispatch_notifications(mode="instant"):
    global _retry_after
    from .database import SessionLocal
    if not begin_notification():
        return {"status": "busy", "sent": 0}
    try:
        if mode == "instant" and monotonic() < _retry_after:
            return {"status": "retry_wait", "sent": 0}
        with SessionLocal() as db:
            result = deliver_notifications(db, mode)
            if result["status"] == "failed":
                _retry_after = monotonic() + 45
            return result
    except Exception:
        _retry_after = monotonic() + 45
        logger.exception("通知任务异常(%s)", mode)
        return {"status": "failed", "sent": 0, "detail": "通知任务异常，请查看服务日志"}
    finally:
        end_notification()


def collect_with_alerts(on_result=None):
    def completed(result):
        if on_result:
            on_result(result)
        # Each completed source can alert immediately; do not wait for slow sources.
        if not result.get("error"):
            dispatch_notifications("instant")
    results = collect_all(on_result=completed)
    dispatch_notifications("instant")
    return results


def run_poll_job():
    from .database import SessionLocal
    with SessionLocal() as db:
        if not setting_bool(db, "collect_enabled", True):
            return
    if not begin_collection():
        return
    try:
        results = collect_with_alerts()
        failures = sum(bool(r.get("error")) for r in results)
        logger.info("定期采集完成: %d 个源，%d 个失败", len(results), failures)
        if failures:
            from .database import SessionLocal
            with SessionLocal() as db:
                _log_alert(db, "UNKNOWN", 0, "failed", f"定期采集: {failures}/{len(results)} 个源失败，请查看监控源状态")
    finally:
        end_collection()


def run_daily_job():
    # Collection has its own interval job. Daily summaries only flush pending data.
    return dispatch_notifications("daily")


# ---------- 调度与页面状态 ----------

POLL_JOB_ID = "poll_vuln_job"
RETRY_JOB_ID = "retry_notifications"
AI_JOB_ID = "ai_summaries"


def _configured_daily_time(db=None):
    from .database import SessionLocal
    own = db is None
    db = db or SessionLocal()
    try:
        return parse_hhmm(crud.get_setting(db, "daily_time", "")) or (config.DAILY_HOUR, config.DAILY_MINUTE)
    finally:
        if own:
            db.close()


def _daily_trigger(hour, minute):
    return CronTrigger(hour=hour, minute=minute, timezone=config.TZ)


def reschedule_daily_job(db=None):
    from .database import SessionLocal
    own = db is None
    db = db or SessionLocal()
    try:
        hour, minute = _configured_daily_time(db)
        if scheduler.running:
            if setting_bool(db, "daily_enabled", True) and setting_bool(db, "notifications_enabled", True):
                current = scheduler.get_job(DAILY_JOB_ID)
                if current and str(current.trigger) == str(_daily_trigger(hour, minute)):
                    return hour, minute
                scheduler.add_job(run_daily_job, _daily_trigger(hour, minute), id=DAILY_JOB_ID,
                                  replace_existing=True, max_instances=1, coalesce=True, misfire_grace_time=3600)
            elif scheduler.get_job(DAILY_JOB_ID):
                scheduler.remove_job(DAILY_JOB_ID)
        return hour, minute
    finally:
        if own:
            db.close()


def reschedule_jobs(db):
    reschedule_daily_job(db)
    if scheduler.running:
        if not setting_bool(db, "collect_enabled", True):
            if scheduler.get_job(POLL_JOB_ID):
                scheduler.remove_job(POLL_JOB_ID)
            return
        minutes = int(crud.get_setting(db, "collect_interval_minutes", "10"))
        current = scheduler.get_job(POLL_JOB_ID)
        if current and current.trigger.interval.total_seconds() == minutes * 60:
            return
        scheduler.add_job(run_poll_job, "interval", minutes=minutes, id=POLL_JOB_ID,
                          replace_existing=True, max_instances=1, coalesce=True, misfire_grace_time=120)


def start_scheduler(db=None):
    if scheduler.running:
        return
    from .database import SessionLocal
    from .ai_worker import run_ai_job
    own = db is None
    db = db or SessionLocal()
    try:
        scheduler.start()
        reschedule_jobs(db)
        scheduler.add_job(dispatch_notifications, "interval", seconds=60, id=RETRY_JOB_ID,
                          max_instances=1, coalesce=True, misfire_grace_time=60)
        scheduler.add_job(run_ai_job, "interval", seconds=60, id=AI_JOB_ID,
                          max_instances=1, coalesce=True, misfire_grace_time=60)
        logger.info("调度已启动: 每 %s 分钟采集，独立即时告警/每日汇总/AI 摘要", crud.get_setting(db, "collect_interval_minutes", "10"))
    finally:
        if own:
            db.close()


def runtime_status(db):
    from .ai_worker import ai_status
    pending, _ = notification_selection(db)
    urgent, _ = notification_selection(db, "instant")
    jobs = {job.id: job.next_run_time.isoformat() if job.next_run_time else None for job in scheduler.get_jobs()}
    latest = db.query(models.SourceCollectionState.last_attempt_at).order_by(models.SourceCollectionState.last_attempt_at.desc()).first()
    return {"timezone": config.TIMEZONE_NAME, "collecting": is_collecting(), "notifying": is_notifying(),
            "collect_interval_minutes": int(crud.get_setting(db, "collect_interval_minutes", "10")),
            "instant_enabled": setting_bool(db, "instant_enabled", True),
            "instant_threshold": crud.get_setting(db, "instant_threshold", "CRITICAL"),
            "collect_enabled": setting_bool(db, "collect_enabled", True),
            "notifications_enabled": setting_bool(db, "notifications_enabled", True),
            "instant_batch_minutes": int(crud.get_setting(db, "instant_batch_minutes", "5")),
            "next_batch_at": instant_batch_due(db, urgent) if _automatic_enabled(db, "instant") else None,
            "alert_max_age_days": int(crud.get_setting(db, "alert_max_age_days", "7")),
            "notify_kev_upgrade": setting_bool(db, "notify_kev_upgrade", True),
            "daily_enabled": setting_bool(db, "daily_enabled", True),
            "daily_time": crud.get_setting(db, "daily_time", "09:00"),
            "next_collect_at": jobs.get(POLL_JOB_ID), "next_daily_at": jobs.get(DAILY_JOB_ID),
            "last_collect_at": latest[0] if latest else None, "pending": len(pending), "urgent_pending": len(urgent),
            "ai": ai_status(db)}


def stop_scheduler():
    if scheduler.running:
        scheduler.shutdown(wait=False)


def collect_elapsed(started_at):
    return round(monotonic() - started_at, 1)
