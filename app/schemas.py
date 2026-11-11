"""Pydantic 请求/响应模型。"""
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

# 支持的采集器类型(与 collectors/base.py 的 mapping 保持一致)
SOURCE_TYPES = Literal[
    "nvd_cpe", "cisa_kev", "rss", "html", "go_osv",
    "chaitin", "oscs", "qianxin_ti", "threatbook", "seebug",
    "struts2", "avd", "venustech",
]


class MonitorSourceBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: str = Field(..., min_length=1, max_length=100)
    source_type: SOURCE_TYPES
    url: str = Field(..., min_length=1, max_length=2000)
    cpe: Optional[str] = Field(None, max_length=500)
    keyword: Optional[str] = Field(None, max_length=500)
    enabled: bool = True


class MonitorSourceCreate(MonitorSourceBase):
    pass


class MonitorSourceUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=200)
    category: Optional[str] = Field(None, min_length=1, max_length=100)
    source_type: Optional[SOURCE_TYPES] = None
    url: Optional[str] = Field(None, min_length=1, max_length=2000)
    cpe: Optional[str] = Field(None, max_length=500)
    keyword: Optional[str] = Field(None, max_length=500)
    enabled: Optional[bool] = None


class MonitorSourceOut(MonitorSourceBase):
    id: int
    created_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityOut(BaseModel):
    id: int
    cve_id: Optional[str]
    unique_key: Optional[str]
    title: str
    severity: Optional[str]
    cvss_score: Optional[float]
    affected: Optional[str]
    tags: Optional[str]
    url: Optional[str]
    published_at: Optional[datetime]
    is_kev: bool
    ai_summary: Optional[str]
    source_id: int
    source_name: Optional[str] = None

    class Config:
        from_attributes = True


class SettingUpdate(BaseModel):
    value: str


class CollectResult(BaseModel):
    source_id: int
    source_name: str
    fetched: int
    new_count: int
    error: Optional[str] = None
