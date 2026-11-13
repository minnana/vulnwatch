"""ORM 模型:监控源、漏洞、配置、推送记录。"""
from sqlalchemy import (
    Boolean, Column, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.orm import relationship

from . import config
from .database import Base


class MonitorSource(Base):
    """监控源配置:一类系统/应用对应的一个数据源。"""
    __tablename__ = "monitor_sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)            # 显示名,如 "Windows Server"
    category = Column(String(100), nullable=False)        # 类别:OS / NAS / Virtualization / WebServer / Database / Runtime
    source_type = Column(String(50), nullable=False)      # nvd_cpe / rss / cisa_kev
    url = Column(Text, nullable=False)                    # API URL / RSS URL / 公告页 URL
    cpe = Column(String(500), nullable=True)              # nvd_cpe 类型的 CPE 匹配串
    keyword = Column(String(500), nullable=True)          # rss 类型的标题过滤关键词(逗号分隔)
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=config.utcnow)

    vulnerabilities = relationship("Vulnerability", back_populates="source", cascade="all, delete-orphan")


class Vulnerability(Base):
    """归一化后的漏洞记录。"""
    __tablename__ = "vulnerabilities"
    __table_args__ = (
        UniqueConstraint("cve_id", "source_id", name="uq_cve_source"),
    )

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(100), index=True, nullable=True)   # CVE 编号(可能为空,如厂商 SA)
    unique_key = Column(String(200), index=True, nullable=True)  # 源内去重键(如 AVD 编号、CT-id、QVD 编号)
    title = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), index=True, nullable=True)  # CRITICAL / HIGH / MEDIUM / LOW
    cvss_score = Column(Float, nullable=True)                 # CVSS v3 评分(0-10)
    affected = Column(Text, nullable=True)                    # 受影响产品/版本
    tags = Column(Text, nullable=True)                        # 标签,逗号分隔(如 预警、POC公开、奇安信CERT验证)
    url = Column(Text, nullable=True)
    published_at = Column(DateTime, index=True, nullable=True)
    first_seen_at = Column(DateTime, default=config.utcnow)
    is_kev = Column(Boolean, default=False)                   # 是否在野利用(CISA KEV)
    ai_summary = Column(Text, nullable=True)                  # DeepSeek 生成的中文摘要(可选)
    source_id = Column(Integer, ForeignKey("monitor_sources.id"), nullable=False)

    source = relationship("MonitorSource", back_populates="vulnerabilities")


class Setting(Base):
    """键值配置:钉钉机器人、告警阈值、DeepSeek、定时等。"""
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(Text, nullable=True)


class AlertLog(Base):
    """推送记录,便于追溯。"""
    __tablename__ = "alert_logs"

    id = Column(Integer, primary_key=True, index=True)
    triggered_at = Column(DateTime, default=config.utcnow)
    severity = Column(String(20), nullable=True)
    count = Column(Integer, default=0)
    status = Column(String(20), default="success")  # success / failed / skipped / silent / baseline
    detail = Column(Text, nullable=True)
