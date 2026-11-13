"""数据库引擎与会话管理。"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import declarative_base, sessionmaker

from . import config

engine = create_engine(
    f"sqlite:///{config.DB_PATH}",
    connect_args={"check_same_thread": False, "timeout": 30},
    # 采集线程 + HTTP 请求线程会同时取连接,连接池不能太小,否则采集高峰期
    # 会出现 "QueuePool limit reached" 等待。
    pool_size=10,
    max_overflow=20,
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_conn, _record):
    """SQLite 并发/可靠性参数。

    - WAL:读写不互斥,采集写库时网页仍可查询;
    - busy_timeout:并发写入时等待锁,而不是立即报 "database is locked";
    - synchronous=NORMAL:WAL 模式下兼顾安全与写入速度;
    - foreign_keys=ON:真正启用外键约束(删除监控源时级联删除依赖 ORM 已处理,
      这里保证误写脏数据时能被数据库拦住)。
    """
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=30000")
    cursor.execute("PRAGMA synchronous=NORMAL")
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_db():
    """FastAPI 依赖:每个请求一个会话,请求结束自动关闭。"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
