"""Pydantic 请求/响应模型。"""
from datetime import datetime
from typing import Dict, List, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# 支持的采集源类型
SOURCE_TYPES = Literal[
    "nvd_cpe",     # NVD CPE 匹配
    "cisa_kev",    # CISA 在野利用清单
    "rss",         # RSS 订阅
    "html",        # 厂商公告页(正则抽取)
    "go_osv",      # Go 官方漏洞库
    "chaitin",     # 长亭漏洞库
    "oscs",        # 安全预警
    "qianxin_ti",  # 奇安信威胁情报中心
    "threatbook",  # 微步在线研究响应中心
    "seebug",      # 知道创宇 Seebug 漏洞库
    "struts2",     # Apache Struts2 安全公告
    "avd",         # 阿里云漏洞库(需 Playwright)
    "venustech",   # 启明星辰漏洞通告(需 Playwright)
]


class MonitorSourceBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    category: str = Field(..., min_length=1, max_length=100)
    source_type: SOURCE_TYPES
    url: str = Field(..., min_length=1, max_length=2000)
    cpe: Optional[str] = Field(None, max_length=500)
    keyword: Optional[str] = Field(None, max_length=500)
    enabled: bool = True

    @field_validator("url")
    @classmethod
    def _check_url_scheme(cls, v: str) -> str:
        """只允许 http/https,避免前端/服务端把奇怪协议当数据源地址。"""
        lower = v.strip().lower()
        if not (lower.startswith("http://") or lower.startswith("https://")):
            raise ValueError("url 必须以 http:// 或 https:// 开头")
        return v.strip()


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

    @field_validator("url")
    @classmethod
    def _check_url_scheme(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        lower = v.strip().lower()
        if not (lower.startswith("http://") or lower.startswith("https://")):
            raise ValueError("url 必须以 http:// 或 https:// 开头")
        return v.strip()


class MonitorSourceOut(MonitorSourceBase):
    id: int
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class VulnerabilityOut(BaseModel):
    id: int
    cve_id: Optional[str] = None
    unique_key: Optional[str] = None
    title: str
    description: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    affected: Optional[str] = None
    tags: Optional[str] = None
    url: Optional[str] = None
    published_at: Optional[datetime] = None
    first_seen_at: Optional[datetime] = None
    is_kev: bool = False
    ai_summary: Optional[str] = None
    source_id: int
    source_name: Optional[str] = None

    model_config = ConfigDict(from_attributes=True)


class VulnerabilityListOut(BaseModel):
    """漏洞列表的分页响应:total 供前端显示总数,items 为当前页数据。"""
    total: int
    items: List[VulnerabilityOut]


class StatsOut(BaseModel):
    """仪表盘统计:一次查询返回全部计数,替代前端 4 次请求。"""
    days: int
    total: int
    critical: int
    high: int
    kev: int
    ai_summary: int


class SettingUpdate(BaseModel):
    value: str = ""


class SettingsUpdate(BaseModel):
    """批量保存配置(前端一次 PUT 提交所有项)。"""
    values: Dict[str, str] = Field(default_factory=dict)


class CollectResult(BaseModel):
    source_id: int
    source_name: str
    fetched: int = 0
    new_count: int = 0
    error: Optional[str] = None


class CollectStatusOut(BaseModel):
    """后台采集任务状态,前端轮询用。"""
    running: bool = False
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    results: List[CollectResult] = Field(default_factory=list)
    error: Optional[str] = None
