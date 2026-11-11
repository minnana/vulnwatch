"""采集编排 + 定时任务。"""
import logging
from datetime import datetime, time as dtime
from typing import List

from apscheduler.schedulers.background import BackgroundScheduler

from . import crud, models
from .collectors import get_collector
from .notifier import CHANNEL_KEYS, build_report, send

logger = logging.getLogger("vulnwatch")
scheduler = BackgroundScheduler(timezone="Asia/Shanghai")


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
        for item in items:
            is_new, obj = crud.upsert_vulnerability(db, source.id, item)
            if is_new:
                result["new_count"] += 1
                result["new_vulns"].append(obj)
    except Exception as e:
        logger.exception(f"采集 {source.name} 失败")
        result["error"] = str(e)
    return result


def collect_all(db) -> List[dict]:
    """采集所有启用的监控源。"""
    sources = crud.list_sources(db, enabled_only=True)
    results = []
    for s in sources:
        r = collect_source(db, s)
        results.append(r)
        logger.info(f"采集 {s.name}: 获取 {r['fetched']} 条, 新增 {r['new_count']} 条")
    return results


# ---------- 过滤逻辑 ----------

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
    haystack = " ".join([v.title or "", v.affected or "", v.cve_id or ""]).lower()
    if include and not any(k in haystack for k in include):
        return False
    if exclude and any(k in haystack for k in exclude):
        return False
    return True


def _match_tags(v, required_tags: List[str]) -> bool:
    """标签过滤:required_tags 非空时,漏洞 tags 需命中至少一个。"""
    if not required_tags:
        return True
    tags = _parse_csv(getattr(v, "tags", None))
    return any(t in tags for t in required_tags)


def _is_silent_time(db) -> bool:
    """静默时段:配置的静默窗口内不推送(默认关闭,可配 00:00-07:00)。"""
    enabled = (crud.get_setting(db, "silent_hours_enabled", "false") or "false").lower() in ("true", "1", "yes")
    if not enabled:
        return False
    start = crud.get_setting(db, "silent_hours_start", "00:00") or "00:00"
    end = crud.get_setting(db, "silent_hours_end", "07:00") or "07:00"
    try:
        s = dtime.fromisoformat(start)
        e = dtime.fromisoformat(end)
    except ValueError:
        return False
    now = datetime.now().time()
    if s < e:
        return s <= now < e
    # 跨天窗口(如 22:00-06:00)
    return now >= s or now < e


def _dedup_by_cve(vulns: List[models.Vulnerability]) -> List[models.Vulnerability]:
    """跨源同一 CVE 去重:有 CVE 的按 cve_id 保留一条(等级最高/评分最高者),
    无 CVE 的(厂商公告)保留 unique_key 唯一。"""
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    seen_cve = {}
    seen_key = set()
    out = []
    # 先按等级/评分排序,保证同 CVE 时保留"最严重"的一条
    ordered = sorted(vulns, key=lambda v: (rank.get(v.severity, 4), -(v.cvss_score or 0)))
    for v in ordered:
        if v.cve_id:
            if v.cve_id in seen_cve:
                continue
            seen_cve[v.cve_id] = v
            out.append(v)
        elif v.unique_key:
            if v.unique_key in seen_key:
                continue
            seen_key.add(v.unique_key)
            out.append(v)
        else:
            out.append(v)
    return out


def _filter_to_push(db, new_vulns: List[models.Vulnerability], threshold: str) -> List[models.Vulnerability]:
    """完整的推送过滤流水线:等级阈值 → 产品黑白名单 → 标签 → 跨源去重。"""
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    th_rank = rank.get(threshold.upper(), 1)

    include = _parse_csv(crud.get_setting(db, "include_keywords", ""))
    exclude = _parse_csv(crud.get_setting(db, "exclude_keywords", ""))
    required_tags = _parse_csv(crud.get_setting(db, "required_tags", ""))

    result = []
    for v in new_vulns:
        # 1. 等级阈值(在野利用 KEV 强制保留)
        if not (v.is_kev or rank.get(v.severity, 4) <= th_rank):
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


def run_daily_job():
    """每日汇总任务:采集 → 过滤 → 推送 → 记录日志。

    只推送「本次采集新增」的漏洞(而非近 24 小时全量),
    这样首次建基线不会轰炸历史数据,后续也只推真实增量。
    """
    from .database import SessionLocal
    db = SessionLocal()
    try:
        results = collect_all(db)
        total_new = sum(r["new_count"] for r in results)

        new_vulns = []
        for r in results:
            new_vulns.extend(r.get("new_vulns", []))

        threshold = crud.get_setting(db, "alert_threshold", "HIGH") or "HIGH"
        to_push = _filter_to_push(db, new_vulns, threshold)

        # 静默时段:静默窗口内只入库不推送
        silent = _is_silent_time(db)

        # 通道路由:读 notify_channel,默认 dingtalk
        channel = crud.get_setting(db, "notify_channel", "dingtalk") or "dingtalk"
        cred_key, secret_key = CHANNEL_KEYS.get(channel, CHANNEL_KEYS["dingtalk"])
        credential = crud.get_setting(db, cred_key, "")
        secret = crud.get_setting(db, secret_key, "") if secret_key else ""

        pushed = 0
        status = "skipped"
        detail = f"新增 {total_new} 条,过滤后 {len(to_push)} 条"

        if silent:
            detail += ",静默时段不推送"
            status = "silent"
            logger.info(f"每日任务:静默时段,跳过推送({total_new} 新增)")
        elif to_push and credential:
            text = build_report(to_push, threshold)
            ok = send(channel, credential, secret, "漏洞情报汇总", text)
            pushed = len(to_push)
            status = "success" if ok else "failed"
            detail += f",推送 {pushed} 条(通道:{channel})"
            log = models.AlertLog(
                severity=threshold,
                count=pushed,
                status=status,
                detail=detail,
            )
            db.add(log)
            db.commit()
        logger.info(f"每日任务完成: 新增 {total_new}, 过滤后 {len(to_push)}, 推送 {pushed} 条 [{status}]")
    finally:
        db.close()


def start_scheduler():
    from . import config as cfg
    if not scheduler.running:
        scheduler.add_job(
            run_daily_job,
            "cron",
            hour=cfg.DAILY_HOUR,
            minute=cfg.DAILY_MINUTE,
            id="daily_vuln_job",
            replace_existing=True,
        )
        scheduler.start()
        logger.info(f"定时任务已启动: 每日 {cfg.DAILY_HOUR:02d}:{cfg.DAILY_MINUTE:02d}")
