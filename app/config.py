"""配置管理:从环境变量读取,Web 界面可覆盖的配置存数据库。"""
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = os.getenv("VULNWATCH_DB", str(DATA_DIR / "vulnwatch.db"))

# 采集器请求间隔(秒):同一域名两次请求之间的最小间隔。
# NVD 官方建议 >= 6s(无 key 时);国内源无需这么长,默认取 1s 兼顾速度与礼貌。
# 可按需用环境变量覆盖:VULNWATCH_REQUEST_INTERVAL
REQUEST_INTERVAL = float(os.getenv("VULNWATCH_REQUEST_INTERVAL", "1.0"))
REQUEST_TIMEOUT = int(os.getenv("VULNWATCH_REQUEST_TIMEOUT", "30"))

# 每日汇总时间(24 小时制)
DAILY_HOUR = int(os.getenv("VULNWATCH_DAILY_HOUR", "9"))
DAILY_MINUTE = int(os.getenv("VULNWATCH_DAILY_MINUTE", "0"))
