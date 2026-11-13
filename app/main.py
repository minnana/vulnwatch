"""FastAPI 应用入口:监控源/漏洞查询/配置/采集触发/静态页面。"""
import base64
import logging
import os
import secrets
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text as sql_text
from sqlalchemy.orm import Session

from . import config, crud, models, schemas
from .database import Base, SessionLocal, engine, get_db
from .notifier import CHANNEL_KEYS, send
from .scheduler import (
    begin_collection,
    collect_all,
    collect_source,
    end_collection,
    is_collecting,
    parse_hhmm,
    reschedule_daily_job,
    start_scheduler,
    stop_scheduler,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("vulnwatch")

APP_VERSION = "0.2.0"
STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# 访问认证口令:通过环境变量 VULNWATCH_AUTH_TOKEN 设置。
# 未设置时(默认)允许匿名访问,便于 demo 与内网部署;
# 一旦设置,所有 API 与页面均需携带该口令(HTTP Basic 或 ?token= 或 Bearer)。
AUTH_TOKEN = os.getenv("VULNWATCH_AUTH_TOKEN", "")

# ---------- 后台采集状态(前端轮询 /api/collect/status) ----------

_collect_state = {
    "running": False,
    "started_at": None,
    "finished_at": None,
    "results": [],
    "error": None,
}
_state_lock = threading.Lock()


def _public_result(r: dict) -> dict:
    """去掉内部字段 new_vulns(可能含 ORM 对象),只保留可序列化字段。"""
    return {
        "source_id": r.get("source_id"),
        "source_name": r.get("source_name"),
        "fetched": r.get("fetched", 0),
        "new_count": r.get("new_count", 0),
        "error": r.get("error"),
    }


def _append_result(r: dict) -> None:
    with _state_lock:
        _collect_state["results"].append(_public_result(r))


def _run_collect_job() -> None:
    """后台线程:采集全部源,期间持续更新状态供前端轮询。"""
    try:
        results = collect_all(on_result=_append_result)
        with _state_lock:
            _collect_state["results"] = [_public_result(r) for r in results]
    except Exception as e:
        logger.exception("后台采集任务失败")
        with _state_lock:
            _collect_state["error"] = str(e)
    finally:
        with _state_lock:
            _collect_state["running"] = False
            _collect_state["finished_at"] = config.utcnow()
        end_collection()


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """启动初始化:建表 → 内置默认监控源/配置 → 启动定时任务;退出时停止。"""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_default_sources(db)
        seed_default_settings(db)
        start_scheduler(db)
    finally:
        db.close()
    logger.info("VulnWatch 已启动 (version=%s)", APP_VERSION)
    yield
    stop_scheduler()
    logger.info("VulnWatch 已停止")


app = FastAPI(title="VulnWatch 漏洞情报监控", version=APP_VERSION, lifespan=lifespan)


# ---------- 访问认证 ----------

def _extract_token(request: Request) -> Optional[str]:
    """从 Authorization / query 中提取口令。"""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    if auth.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth[6:].strip()).decode("utf-8")
        except Exception:
            return None
        # Basic 形式约定为任意用户名:口令,只比较口令部分
        _user, sep, password = decoded.partition(":")
        return password if sep else decoded
    return request.query_params.get("token")


def _is_public_path(path: str) -> bool:
    # 页面与静态资源不做口令校验:浏览器加载 <script>/<link> 时无法附加 Authorization 头,
    # 若把 / 与 /static/* 一并保护,设置 VULNWATCH_AUTH_TOKEN 后页面会直接显示 401。
    # 页面本身不含数据,所有数据接口仍然需要口令。
    if path in ("/", "/favicon.ico", "/api/health"):
        return True
    return path.startswith("/static/")


def _check_token(request: Request) -> bool:
    if not AUTH_TOKEN:
        return True
    token = _extract_token(request) or ""
    # 先按 UTF-8 编码再比较:compare_digest 对含非 ASCII 字符的 str 会抛 TypeError(500),
    # 而口令来自环境变量/URL,用户完全可能用中文。
    return secrets.compare_digest(token.encode("utf-8"), AUTH_TOKEN.encode("utf-8"))


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    # 页面与静态资源公开(见 _is_public_path);数据接口未通过认证返回 401
    if not _is_public_path(request.url.path) and not _check_token(request):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "未授权:缺少或错误的访问口令"}, status_code=401)
        return JSONResponse(
            {"detail": "未授权:请在 URL 后附加 ?token= 或设置 Authorization 头"},
            status_code=401,
        )
    return await call_next(request)


# ---------- 安全响应头中间件 ----------
# 注意:该中间件必须在 auth_guard 之后注册,才能包住 401 响应(反之 401 没有安全头)。

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'",
    )
    if request.url.path.startswith("/api/"):
        # 漏洞/配置数据不缓存,避免共享终端看到过期或他人数据
        response.headers.setdefault("Cache-Control", "no-store")
    return response


# ---------- 启动初始化数据 ----------

def seed_default_sources(db: Session):
    """首次启动内置默认监控源。"""
    if crud.list_sources(db):
        return
    defaults = [
        # 操作系统
        ("Windows Server", "OS", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "Windows"),
        ("Linux 内核", "OS", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "Linux"),
        # NAS
        ("群晖 NAS (DSM)", "NAS", "html", "https://www.synology.com/zh-cn/security/advisory", None, None),
        ("QNAP NAS", "NAS", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "QNAP"),
        # 虚拟化
        ("VMware ESXi / vCenter", "Virtualization", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "VMware"),
        # Web 服务器
        ("IIS", "WebServer", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "IIS"),
        ("Nginx", "WebServer", "html", "https://nginx.org/en/security_advisories.html", None, None),
        ("Apache HTTP Server", "WebServer", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "httpd"),
        # 数据库
        ("MySQL", "Database", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "MySQL"),
        ("PostgreSQL", "Database", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "PostgreSQL"),
        ("Microsoft SQL Server", "Database", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "SQL Server"),
        ("Redis", "Database", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "Redis"),
        ("MongoDB", "Database", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "MongoDB"),
        ("Oracle Database", "Database", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "Oracle"),
        # 语言运行时
        ("Go (标准库/工具链)", "Runtime", "go_osv", "https://vuln.go.dev/index/vulns.json", None, None),
        ("Node.js", "Runtime", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "Node.js"),
        ("Python", "Runtime", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "Python"),
        ("Java (OpenJDK)", "Runtime", "nvd_cpe", "https://services.nvd.nist.gov/rest/json/cves/2.0", None, "OpenJDK"),
        # 微软官方补丁公告(RSS)
        ("Microsoft 安全更新 (MSRC)", "OS", "rss", "https://api.msrc.microsoft.com/update-guide/rss", None, None),
        # 在野利用情报(单独高亮)
        ("CISA 在野利用漏洞 (KEV)", "Intelligence", "cisa_kev", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", None, None),
        # ---- 国内漏洞源(参考 watchvuln)----
        ("阿里云漏洞库 (AVD)", "Intelligence", "avd", "https://avd.aliyun.com/high-risk/list", None, None, False),
        ("长亭漏洞库", "Intelligence", "chaitin", "https://stack.chaitin.com/api/v2/vuln/list/", None, None),
        ("OSCS 开源安全情报预警", "Intelligence", "oscs", "https://www.oscs1024.com/oscs/v1/intelligence/list", None, None),
        ("奇安信威胁情报中心", "Intelligence", "qianxin_ti", "https://ti.qianxin.com/alpha-api/v2/vuln/one-day", None, None),
        ("微步在线研究响应中心", "Intelligence", "threatbook", "https://x.threatbook.com/v5/node/vul_module/homePage", None, None),
        ("知道创宇 Seebug 漏洞库", "Intelligence", "seebug", "https://www.seebug.org/vuldb/vulnerabilities", None, None),
        ("启明星辰漏洞通告", "Intelligence", "venustech", "https://www.venustech.com.cn/new_type/aqtg/", None, None, False),
        ("Apache Struts2 安全公告", "WebServer", "struts2", "https://cwiki.apache.org/confluence/display/WW/Security+Bulletins", None, None),
    ]
    for item in defaults:
        name, cat, stype, url, cpe, kw = item[:6]
        enabled = item[6] if len(item) > 6 else True
        db.add(models.MonitorSource(
            name=name, category=cat, source_type=stype, url=url,
            cpe=cpe, keyword=kw, enabled=enabled,
        ))
    db.commit()
    logger.info("已内置默认监控源")


def seed_default_settings(db: Session):
    """补齐默认配置项(不覆盖用户已改过的值)。"""
    defaults = {
        "notify_channel": "dingtalk",
        "alert_threshold": "HIGH",
        "silent_hours_enabled": "false",
        "silent_hours_start": "00:00",
        "silent_hours_end": "07:00",
        "daily_time": f"{config.DAILY_HOUR:02d}:{config.DAILY_MINUTE:02d}",
        "include_keywords": "",
        "exclude_keywords": "",
        "required_tags": "",
    }
    existing = crud.get_all_settings(db)
    missing = {k: v for k, v in defaults.items() if k not in existing}
    if missing:
        crud.set_settings(db, missing)


# ---------- 监控源 API ----------

@app.get("/api/sources", response_model=list[schemas.MonitorSourceOut])
def api_list_sources(db: Session = Depends(get_db)):
    return crud.list_sources(db)


@app.post("/api/sources", response_model=schemas.MonitorSourceOut)
def api_create_source(data: schemas.MonitorSourceCreate, db: Session = Depends(get_db)):
    return crud.create_source(db, data)


@app.get("/api/sources/{source_id}", response_model=schemas.MonitorSourceOut)
def api_get_source(source_id: int, db: Session = Depends(get_db)):
    s = crud.get_source(db, source_id)
    if not s:
        raise HTTPException(404, "监控源不存在")
    return s


@app.put("/api/sources/{source_id}", response_model=schemas.MonitorSourceOut)
def api_update_source(source_id: int, data: schemas.MonitorSourceUpdate, db: Session = Depends(get_db)):
    s = crud.update_source(db, source_id, data)
    if not s:
        raise HTTPException(404, "监控源不存在")
    return s


@app.delete("/api/sources/{source_id}")
def api_delete_source(source_id: int, db: Session = Depends(get_db)):
    if not crud.delete_source(db, source_id):
        raise HTTPException(404, "监控源不存在")
    return {"ok": True}


# ---------- 漏洞查询 API ----------

@app.get("/api/vulnerabilities", response_model=schemas.VulnerabilityListOut)
def api_list_vulns(
    severity: Optional[str] = Query(None, pattern="^(CRITICAL|HIGH|MEDIUM|LOW|UNKNOWN)$"),
    keyword: Optional[str] = Query(None, max_length=200),
    is_kev: Optional[bool] = None,
    days: int = Query(7, ge=1, le=365),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
):
    items, total = crud.list_vulnerabilities(db, severity, keyword, is_kev, days, limit, offset)
    return {"total": total, "items": items}


@app.get("/api/stats", response_model=schemas.StatsOut)
def api_stats(days: int = Query(7, ge=1, le=365), db: Session = Depends(get_db)):
    """仪表盘统计:一次查询返回全部计数(替代前端多次请求)。"""
    return crud.stats(db, days)


# ---------- 配置 API ----------

@app.get("/api/settings")
def api_get_settings(db: Session = Depends(get_db)):
    return crud.get_all_settings(db)


@app.put("/api/settings/{key}")
def api_set_setting(key: str, data: schemas.SettingUpdate, db: Session = Depends(get_db)):
    if key == "daily_time" and parse_hhmm(data.value) is None:
        raise HTTPException(400, "daily_time 格式应为 HH:MM")
    crud.set_setting(db, key, data.value)
    if key == "daily_time":
        reschedule_daily_job(db)
    return {"ok": True}


@app.put("/api/settings")
def api_set_settings(data: schemas.SettingsUpdate, db: Session = Depends(get_db)):
    """批量保存配置(前端一次请求提交所有项)。"""
    values = dict(data.values)
    if "daily_time" in values:
        raw = (values.get("daily_time") or "").strip()
        if raw:
            if parse_hhmm(raw) is None:
                raise HTTPException(400, "daily_time 格式应为 HH:MM")
            values["daily_time"] = raw
        else:
            # 留空表示沿用默认时间:只跳过该项,不要因为一项为空让整批配置保存失败
            values.pop("daily_time")
    channel = values.get("notify_channel")
    if channel and channel not in CHANNEL_KEYS:
        raise HTTPException(400, f"不支持的通知通道: {channel}")
    if values:
        crud.set_settings(db, values)
    if "daily_time" in values:
        reschedule_daily_job(db)
    return {"ok": True}


# ---------- 采集触发 API ----------

@app.post("/api/collect")
def api_collect():
    """手动触发全量采集:立即返回,后台执行,前端轮询 /api/collect/status。"""
    if not begin_collection(blocking=False):
        raise HTTPException(409, "已有采集任务正在运行,请稍后再试")
    with _state_lock:
        _collect_state.update({
            "running": True,
            "started_at": config.utcnow(),
            "finished_at": None,
            "results": [],
            "error": None,
        })
    threading.Thread(target=_run_collect_job, name="vulnwatch-collect", daemon=True).start()
    return {"started": True}


@app.get("/api/collect/status", response_model=schemas.CollectStatusOut)
def api_collect_status():
    with _state_lock:
        state = dict(_collect_state)
        state["results"] = [_public_result(r) for r in state.get("results") or []]
    if is_collecting() and not state["running"]:
        # 定时任务正在跑(不是 Web 触发的),也告知前端
        state["running"] = True
    return state


@app.post("/api/collect/{source_id}")
def api_collect_one(source_id: int, db: Session = Depends(get_db)):
    """单独采集某个监控源(同步,通常只有 1 个源,耗时可控)。"""
    s = crud.get_source(db, source_id)
    if not s:
        raise HTTPException(404, "监控源不存在")
    r = collect_source(db, s)
    return _public_result(r)


# ---------- 通知测试 ----------

def _do_test_notify(db: Session, channel: Optional[str] = None) -> dict:
    channel = (channel or crud.get_setting(db, "notify_channel", "dingtalk") or "dingtalk").strip().lower()
    if channel not in CHANNEL_KEYS:
        return {"ok": False, "channel": channel, "msg": f"不支持的通知通道: {channel}"}
    cred_key, secret_key = CHANNEL_KEYS[channel]
    credential = crud.get_setting(db, cred_key, "") or ""
    secret = (crud.get_setting(db, secret_key, "") or "") if secret_key else ""
    if not credential:
        return {"ok": False, "channel": channel, "msg": f"未配置 {channel} 的凭证({cred_key})"}
    ok = send(channel, credential, secret, "VulnWatch 测试", "这是一条来自 VulnWatch 的测试消息 ✅")
    return {"ok": ok, "channel": channel}


@app.post("/api/test-dingtalk")
def api_test_dingtalk(db: Session = Depends(get_db)):
    """测试通知(兼容旧路径,默认钉钉通道)。"""
    return _do_test_notify(db, "dingtalk")


@app.post("/api/test-notify")
@app.post("/api/test-notify/{channel}")
def api_test_notify(channel: Optional[str] = None, db: Session = Depends(get_db)):
    """测试通知:按 notify_channel 配置路由到对应通道。"""
    return _do_test_notify(db, channel)


# ---------- 健康检查 ----------

@app.get("/api/health")
def api_health():
    """容器健康检查/监控探活(不需要口令)。"""
    db_ok = True
    try:
        db = SessionLocal()
        try:
            db.execute(sql_text("SELECT 1"))
        finally:
            db.close()
    except Exception as e:
        db_ok = False
        logger.warning("健康检查数据库异常: %s", e)
    return {
        "status": "ok" if db_ok else "degraded",
        "version": APP_VERSION,
        "time": config.now_local().isoformat(),
        "database": "ok" if db_ok else "error",
        "collecting": is_collecting(),
    }


# ---------- 静态页面 ----------

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
