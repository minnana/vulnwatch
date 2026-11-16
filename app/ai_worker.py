"""Bounded asynchronous enrichment of successfully notified public advisories."""
import threading
from datetime import timedelta, timezone
from sqlalchemy import func

from . import config, crud, models
from .database import SessionLocal
from .summarize import summarize_vuln

_lock = threading.Lock()


def _day_start():
    return config.now_local().replace(hour=0, minute=0, second=0, microsecond=0).astimezone(timezone.utc).replace(tzinfo=None)


def ai_status(db):
    used = db.query(func.count(models.AIAttempt.id)).filter(models.AIAttempt.attempted_at >= _day_start()).scalar() or 0
    last = db.query(models.AIAttempt).order_by(models.AIAttempt.id.desc()).first()
    return {"enabled": crud.get_setting(db, "ai_enabled", "false") == "true",
            "configured": bool(crud.get_setting(db, "deepseek_api_key", "")),
            "model": crud.get_setting(db, "ai_model", config.AI_MODEL),
            "calls_today": int(used), "daily_limit": int(crud.get_setting(db, "ai_daily_limit", "20")),
            "running": _lock.locked(), "last_status": last.status if last else None}


def run_ai_job():
    if not _lock.acquire(blocking=False):
        return
    try:
        with SessionLocal() as db:
            state = ai_status(db)
            if not state["enabled"] or not state["configured"]:
                return
            budget = min(int(crud.get_setting(db, "ai_batch_limit", "5")),
                         max(0, state["daily_limit"] - state["calls_today"]))
            if not budget:
                return
            # Only enrich actual alerts, never process the initial historical baseline.
            sent_keys = {r[0] for r in db.query(models.NotificationReceipt.event_key).filter_by(status="sent").all()}
            recent_attempts = {r[0] for r in db.query(models.AIAttempt.event_key).filter(
                models.AIAttempt.attempted_at >= config.utcnow() - timedelta(hours=1)).all()}
            rows = db.query(models.Vulnerability).filter(models.Vulnerability.ai_summary.is_(None)).all()
            from .scheduler import _dedup_by_cve
            rows = _dedup_by_cve([v for v in rows if crud.notification_key(v) in sent_keys
                                  and crud.notification_key(v) not in recent_attempts])
            api_key = crud.get_setting(db, "deepseek_api_key", "")
            for row in rows[:budget]:
                event_key = crud.notification_key(row)
                attempt = models.AIAttempt(event_key=event_key, status="running")
                db.add(attempt)
                db.commit()  # Count the request before calling the API, even if the process exits.
                try:
                    summary = summarize_vuln(api_key, row, model=state["model"])
                except Exception:
                    summary = ""
                attempt.status = "success" if summary else "failed"
                if summary:
                    # Cache across sources for the same CVE.
                    matching = db.query(models.Vulnerability).filter_by(cve_id=row.cve_id).all() if row.cve_id else [row]
                    for item in matching:
                        item.ai_summary = summary
                db.commit()
    finally:
        _lock.release()
