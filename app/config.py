"""配置管理:环境变量读取 + 运行期常量。

Web 界面可覆盖的配置(通知凭证、阈值、黑白名单、定时时间等)存数据库,
其余进程级参数走环境变量,便于容器化部署。
"""
import os
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("VULNWATCH_DATA_DIR", str(BASE_DIR / "data")))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DB_PATH = os.getenv("VULNWATCH_DB", str(DATA_DIR / "vulnwatch.db"))

# ---------- 时区 ----------
# 业务时区:定时任务、静默时段、报告标题时间统一按它计算。
# 服务器时区(容器 TZ)可能不是东八区,不能直接依赖 datetime.now()。
TIMEZONE_NAME = os.getenv("VULNWATCH_TIMEZONE", "Asia/Shanghai")
try:
    TZ = ZoneInfo(TIMEZONE_NAME)
except ZoneInfoNotFoundError:  # 系统缺少 tzdata 时退回 UTC,不中断服务
    TZ = timezone.utc


def now_local() -> datetime:
    """业务时区下的当前时间(带时区)。"""
    return datetime.now(TZ)


def utcnow() -> datetime:
    """数据库统一存储的 naive UTC 时间。

    兼容既有数据:历史记录的 first_seen_at / published_at 都是 naive UTC,
    因此这里也返回 naive 值,只是不再使用已废弃的 datetime.utcnow()。
    """
    return datetime.now(timezone.utc).replace(tzinfo=None)


# ---------- 采集 ----------
# 同一域名两次请求之间的最小间隔(秒)。NVD 官方建议无 API key 时 >= 6 秒,
# NVD 采集器在自身内部单独覆盖为 NVD_REQUEST_INTERVAL。
REQUEST_INTERVAL = float(os.getenv("VULNWATCH_REQUEST_INTERVAL", "1.0"))
REQUEST_TIMEOUT = int(os.getenv("VULNWATCH_REQUEST_TIMEOUT", "30"))
RETRY_TIMES = int(os.getenv("VULNWATCH_RETRY_TIMES", "2"))

# 并行采集的监控源数量。SQLite 已开 WAL,8 个线程写压力可控;
# 若部署在慢速磁盘/网络环境,可下调为 2~4。
COLLECT_MAX_WORKERS = max(1, int(os.getenv("VULNWATCH_COLLECT_WORKERS", "8")))

# ---------- NVD 批量模式 ----------
# 默认有 15 个监控源都走 NVD。逐个源按关键词查询需要 15 次 API 调用,
# 批量模式改为「按时间范围一次拉全量,再在本地按关键词过滤」,
# 通常 1~3 次请求即可覆盖所有 NVD 源,采集耗时从数分钟降到十几秒。
NVD_BULK_ENABLED = os.getenv("VULNWATCH_NVD_BULK", "1").strip().lower() not in ("0", "false", "no", "off")
NVD_DAYS = int(os.getenv("VULNWATCH_NVD_DAYS", "7"))            # 拉取最近 N 天
NVD_PAGE_SIZE = int(os.getenv("VULNWATCH_NVD_PAGE_SIZE", "2000"))  # NVD 单页上限 2000
NVD_MAX_PAGES = int(os.getenv("VULNWATCH_NVD_MAX_PAGES", "5"))     # 兜底,避免异常翻页
NVD_REQUEST_INTERVAL = float(os.getenv("VULNWATCH_NVD_INTERVAL", "6.0"))
NVD_CACHE_TTL = int(os.getenv("VULNWATCH_NVD_CACHE_TTL", "600"))   # 批量结果缓存秒数

# Go 漏洞库详情并发数(静态 JSON,小并发可把 60 次请求从 1 分钟降到数秒)
OSV_CONCURRENCY = max(1, int(os.getenv("VULNWATCH_OSV_CONCURRENCY", "6")))

# ---------- 推送 ----------
# 单条消息的 UTF-8 字节上限。钉钉 markdown 上限 20000 字节、企微 4096 字节,
# 统一按最严格通道取值可通过环境变量调整;超长报告会自动分条发送。
PUSH_MAX_BYTES = int(os.getenv("VULNWATCH_PUSH_MAX_BYTES", "3600"))

# ---------- 定时任务 ----------
DAILY_HOUR = int(os.getenv("VULNWATCH_DAILY_HOUR", "9"))
DAILY_MINUTE = int(os.getenv("VULNWATCH_DAILY_MINUTE", "0"))

# ---------- DeepSeek(可选增强) ----------
AI_MODEL = os.getenv("VULNWATCH_AI_MODEL", "deepseek-chat")
AI_SUMMARY_LIMIT = int(os.getenv("VULNWATCH_AI_SUMMARY_LIMIT", "5"))  # 每次推送最多生成几条摘要
AI_TIMEOUT = int(os.getenv("VULNWATCH_AI_TIMEOUT", "60"))
