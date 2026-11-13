"""数据库读写操作。"""
from datetime import timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session, joinedload

from . import config, models, schemas

# 需要写回数据库的漏洞字段(upsert 用)
_VULN_FIELDS = (
    "cve_id", "unique_key", "title", "description", "severity", "cvss_score",
    "affected", "tags", "url", "published_at", "is_kev", "ai_summary",
)


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

def _clean(data: dict) -> dict:
    """归一化:空字符串视为 None;CVE 编号统一大写;标题兜底。"""
    clean = {}
    for k in _VULN_FIELDS:
        v = data.get(k)
        if isinstance(v, str) and not v.strip():
            v = None
        if k == "cve_id" and isinstance(v, str):
            v = v.upper()
        clean[k] = v
    if not clean.get("title"):
        clean["title"] = clean.get("cve_id") or clean.get("unique_key") or "未命名漏洞"
    return clean


def upsert_many(db: Session, source_id: int, items: Iterable[dict]) -> Tuple[int, List[dict]]:
    """批量插入/更新某个源采集到的漏洞。

    相比逐条 upsert:整个批次只做一次"预加载已有记录"查询和一次 commit,
    避免每条记录一次 SELECT + INSERT/UPDATE + refresh(单次采集可省数千次往返)。
    返回 (新增数量, 新增记录列表[dict])。
    """
    rows = [_clean(dict(it)) for it in items]
    if not rows:
        return 0, []

    # 一次性取出该源已有记录,建立两级索引(unique_key 优先,其次 cve_id)
    existing = (
        db.query(models.Vulnerability)
        .filter(models.Vulnerability.source_id == source_id)
        .all()
    )
    by_key: Dict[str, models.Vulnerability] = {}
    by_cve: Dict[str, models.Vulnerability] = {}
    for row in existing:
        if row.unique_key:
            by_key.setdefault(row.unique_key, row)
        if row.cve_id:
            by_cve.setdefault(row.cve_id, row)

    new_pairs = []  # [(data, obj)]
    for data in rows:
        obj = None
        if data["unique_key"]:
            obj = by_key.get(data["unique_key"])
        if obj is None and data["cve_id"]:
            obj = by_cve.get(data["cve_id"])
        if obj is not None:
            # 只更新有变化的字段,避免无意义写放大
            for k, v in data.items():
                if k == "ai_summary" and v is None:
                    # 采集器不提供 AI 摘要;重新采集时不能把已生成的中文摘要清空
                    continue
                if getattr(obj, k, None) != v:
                    setattr(obj, k, v)
            continue

        obj = models.Vulnerability(source_id=source_id, **data)
        db.add(obj)
        if data["unique_key"]:
            by_key[data["unique_key"]] = obj
        if data["cve_id"]:
            by_cve[data["cve_id"]] = obj
        new_pairs.append((data, obj))

    db.flush()  # 分配自增 id
    new_items: List[dict] = []
    for data, obj in new_pairs:
        data["id"] = obj.id
        data["source_id"] = source_id
        data["is_new"] = True
        new_items.append(data)
    db.commit()
    return len(new_items), new_items


def upsert_vulnerability(db: Session, source_id: int, data: dict) -> Tuple[bool, dict]:
    """单条插入/更新(保留给外部/脚本调用),内部复用批量实现。"""
    is_new, items = upsert_many(db, source_id, [data])
    return is_new > 0, (items[0] if items else data)


def list_vulnerabilities(
    db: Session,
    severity: Optional[str] = None,
    keyword: Optional[str] = None,
    is_kev: Optional[bool] = None,
    days: int = 7,
    limit: int = 100,
    offset: int = 0,
) -> Tuple[List[models.Vulnerability], int]:
    q = db.query(models.Vulnerability).options(joinedload(models.Vulnerability.source))
    if days > 0:
        since = config.utcnow() - timedelta(days=days)
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
        q.order_by(models.Vulnerability.published_at.desc().nullslast(), models.Vulnerability.id.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    # 附加 source_name(关系已 joinedload,不会产生额外查询)
    for it in items:
        it.source_name = it.source.name if it.source else None
    return items, total


def count_vulnerabilities(db: Session) -> int:
    """库里已有漏洞总数,用于判断"首次采集基线"。"""
    return int(db.query(func.count(models.Vulnerability.id)).scalar() or 0)


def stats(db: Session, days: int = 7) -> dict:
    """仪表盘统计:一次聚合查询返回总数/严重/高危/KEV/已生成摘要数。"""
    since = config.utcnow() - timedelta(days=days)
    row = db.query(
        func.count(models.Vulnerability.id),
        func.sum(case((models.Vulnerability.severity == "CRITICAL", 1), else_=0)),
        func.sum(case((models.Vulnerability.severity == "HIGH", 1), else_=0)),
        func.sum(case((models.Vulnerability.is_kev.is_(True), 1), else_=0)),
        func.sum(case((models.Vulnerability.ai_summary.isnot(None), 1), else_=0)),
    ).filter(
        or_(
            models.Vulnerability.published_at >= since,
            models.Vulnerability.first_seen_at >= since,
        )
    ).one()
    return {
        "days": days,
        "total": int(row[0] or 0),
        "critical": int(row[1] or 0),
        "high": int(row[2] or 0),
        "kev": int(row[3] or 0),
        "ai_summary": int(row[4] or 0),
    }


def update_ai_summaries(db: Session, mapping: Dict[int, str]) -> int:
    """批量写回 AI 摘要,vuln_id -> summary。"""
    if not mapping:
        return 0
    rows = (
        db.query(models.Vulnerability)
        .filter(models.Vulnerability.id.in_(list(mapping.keys())))
        .all()
    )
    for row in rows:
        row.ai_summary = mapping.get(row.id)
    db.commit()
    return len(rows)


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


def set_settings(db: Session, values: Dict[str, str]) -> None:
    """批量保存配置(一次 commit)。"""
    if not values:
        return
    existing = {
        s.key: s
        for s in db.query(models.Setting).filter(models.Setting.key.in_(list(values.keys()))).all()
    }
    for key, value in values.items():
        s = existing.get(key)
        if s:
            s.value = value
        else:
            db.add(models.Setting(key=key, value=value))
    db.commit()


def get_all_settings(db: Session) -> dict:
    return {s.key: s.value for s in db.query(models.Setting).all()}
