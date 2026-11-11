"""数据库读写操作。"""
from datetime import datetime, timedelta
from typing import List, Optional

from sqlalchemy import or_
from sqlalchemy.orm import Session

from . import models, schemas


# ---------- MonitorSource ----------

def list_sources(db: Session, enabled_only: bool = False) -> List[models.MonitorSource]:
    q = db.query(models.MonitorSource)
    if enabled_only:
        q = q.filter(models.MonitorSource.enabled.is_(True))
    return q.order_by(models.MonitorSource.category, models.MonitorSource.name).all()


def get_source(db: Session, source_id: int) -> Optional[models.MonitorSource]:
    return db.query(models.MonitorSource).filter(models.MonitorSource.id == source_id).first()


def create_source(db: Session, data: schemas.MonitorSourceCreate) -> models.MonitorSource:
    s = models.MonitorSource(**data.model_dump())
    db.add(s)
    db.commit()
    db.refresh(s)
    return s


def update_source(db: Session, source_id: int, data: schemas.MonitorSourceUpdate) -> Optional[models.MonitorSource]:
    s = get_source(db, source_id)
    if not s:
        return None
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(s, k, v)
    db.commit()
    db.refresh(s)
    return s


def delete_source(db: Session, source_id: int) -> bool:
    s = get_source(db, source_id)
    if not s:
        return False
    db.delete(s)
    db.commit()
    return True


# ---------- Vulnerability ----------

def upsert_vulnerability(db: Session, source_id: int, data: dict) -> tuple[bool, models.Vulnerability]:
    """插入或更新漏洞。返回 (是否新增, 记录)。

    去重优先级:unique_key > cve_id,均按 source_id 限定。
    """
    # 归一化:空字符串视为 None,避免 UNIQUE 约束冲突
    clean = {}
    for k, v in data.items():
        if isinstance(v, str) and v == "":
            clean[k] = None
        else:
            clean[k] = v
    data = clean

    unique_key = data.get("unique_key")
    cve_id = data.get("cve_id")
    existing = None
    if unique_key:
        existing = (
            db.query(models.Vulnerability)
            .filter(models.Vulnerability.unique_key == unique_key, models.Vulnerability.source_id == source_id)
            .first()
        )
    if existing is None and cve_id:
        existing = (
            db.query(models.Vulnerability)
            .filter(models.Vulnerability.cve_id == cve_id, models.Vulnerability.source_id == source_id)
            .first()
        )
    if existing:
        is_new = False
        for k, v in data.items():
            setattr(existing, k, v)
        obj = existing
    else:
        is_new = True
        obj = models.Vulnerability(source_id=source_id, **data)
        db.add(obj)
    db.commit()
    db.refresh(obj)
    return is_new, obj


def list_vulnerabilities(
    db: Session,
    severity: Optional[str] = None,
    keyword: Optional[str] = None,
    is_kev: Optional[bool] = None,
    days: int = 7,
    limit: int = 100,
    offset: int = 0,
) -> tuple[List[models.Vulnerability], int]:
    q = db.query(models.Vulnerability)
    if days > 0:
        since = datetime.utcnow() - timedelta(days=days)
        # 有发布日期的按发布日期;无发布日期的按首次入库时间判断
        q = q.filter(
            or_(
                models.Vulnerability.published_at >= since,
                models.Vulnerability.first_seen_at >= since,
            )
        )
    if severity:
        q = q.filter(models.Vulnerability.severity == severity.upper())
    if is_kev is not None:
        q = q.filter(models.Vulnerability.is_kev.is_(is_kev))
    if keyword:
        like = f"%{keyword}%"
        q = q.filter(
            or_(
                models.Vulnerability.title.like(like),
                models.Vulnerability.cve_id.like(like),
                models.Vulnerability.affected.like(like),
            )
        )
    total = q.count()
    items = (
        q.order_by(models.Vulnerability.published_at.desc().nullslast())
        .offset(offset)
        .limit(limit)
        .all()
    )
    # 附加 source_name
    for it in items:
        if it.source:
            it.source_name = it.source.name
    return items, total


def get_recent_vulns(db: Session, since_hours: int = 24) -> List[models.Vulnerability]:
    since = datetime.utcnow() - timedelta(hours=since_hours)
    return (
        db.query(models.Vulnerability)
        .filter(
            or_(
                models.Vulnerability.published_at >= since,
                models.Vulnerability.first_seen_at >= since,
            )
        )
        .all()
    )


# ---------- Settings ----------

def get_setting(db: Session, key: str, default: Optional[str] = None) -> Optional[str]:
    s = db.query(models.Setting).filter(models.Setting.key == key).first()
    return s.value if s else default


def set_setting(db: Session, key: str, value: str) -> None:
    s = db.query(models.Setting).filter(models.Setting.key == key).first()
    if s:
        s.value = value
    else:
        s = models.Setting(key=key, value=value)
        db.add(s)
    db.commit()


def get_all_settings(db: Session) -> dict:
    return {s.key: s.value for s in db.query(models.Setting).all()}
