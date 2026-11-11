"""FastAPI 入口:API + 静态页面 + 启动初始化。"""
import logging
import os
import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from . import crud, models, schemas
from .database import Base, SessionLocal, engine, get_db
from .notifier import CHANNEL_KEYS, send
from .scheduler import collect_all, collect_source, start_scheduler

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")
logger = logging.getLogger("vulnwatch")

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# 访问认证口令:通过环境变量 VULNWATCH_AUTH_TOKEN 设置。
# 未设置时(默认)允许匿名访问,便于 demo 与内网部署;
# 一旦设置,所有 API 与页面均需携带该口令(HTTP Basic 或 ?token= 或 Bearer)。
AUTH_TOKEN = os.getenv("VULNWATCH_AUTH_TOKEN", "")

app = FastAPI(title="VulnWatch 漏洞情报监控", version="0.1.0")


# ---------- 安全响应头中间件 ----------

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("X-XSS-Protection", "1; mode=block")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
    )
    return response


# ---------- 访问认证 ----------

def _check_token(request: Request) -> bool:
    if not AUTH_TOKEN:
        return True
    # Bearer / token query / Basic Auth 三种方式
    auth = request.headers.get("authorization", "")
    if auth.startswith("Bearer "):
        return secrets.compare_digest(auth[7:].strip(), AUTH_TOKEN)
    if auth.startswith("Basic "):
        import base64
        try:
            decoded = base64.b64decode(auth[6:].strip()).decode("utf-8")
        except Exception:
            return False
        return secrets.compare_digest(decoded, f":{AUTH_TOKEN}")
    token = request.query_params.get("token", "")
    return secrets.compare_digest(token, AUTH_TOKEN)


@app.middleware("http")
async def auth_guard(request: Request, call_next):
    # 静态资源与页面一并保护;未通过认证返回 401
    if not _check_token(request):
        if request.url.path.startswith("/api/"):
            return JSONResponse({"detail": "未授权:缺少或错误的访问口令"}, status_code=401)
        return JSONResponse({"detail": "未授权:请在 URL 后附加 ?token= 或设置 Authorization 头"}, status_code=401)
    return await call_next(request)


# ---------- 启动初始化 ----------

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
        db.add(models.MonitorSource(name=name, category=cat, source_type=stype, url=url, cpe=cpe, keyword=kw, enabled=enabled))
    db.commit()
    logger.info("已内置默认监控源")


@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_default_sources(db)
    finally:
        db.close()
    start_scheduler()


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

@app.get("/api/vulnerabilities")
def api_list_vulns(
    severity: str = None,
    keyword: str = None,
    is_kev: bool = None,
    days: int = 7,
    limit: int = 100,
    offset: int = 0,
    db: Session = Depends(get_db),
):
    items, total = crud.list_vulnerabilities(db, severity, keyword, is_kev, days, limit, offset)
    return {
        "total": total,
        "items": [
            {
                "id": v.id,
                "cve_id": v.cve_id,
                "unique_key": v.unique_key,
                "title": v.title,
                "severity": v.severity,
                "cvss_score": v.cvss_score,
                "affected": v.affected,
                "tags": v.tags,
                "url": v.url,
                "published_at": v.published_at.isoformat() if v.published_at else None,
                "is_kev": v.is_kev,
                "ai_summary": v.ai_summary,
                "source_name": v.source.name if v.source else None,
            }
            for v in items
        ],
    }


# ---------- 配置 API ----------

@app.get("/api/settings")
def api_get_settings(db: Session = Depends(get_db)):
    return crud.get_all_settings(db)


@app.put("/api/settings/{key}")
def api_set_setting(key: str, data: schemas.SettingUpdate, db: Session = Depends(get_db)):
    crud.set_setting(db, key, data.value)
    return {"ok": True}


# ---------- 采集触发 API ----------

@app.post("/api/collect")
def api_collect(db: Session = Depends(get_db)):
    """手动触发全量采集。"""
    results = collect_all(db)
    # 去掉内部字段 new_vulns(含 SQLAlchemy 对象),避免序列化失败
    return {"results": [{k: v for k, v in r.items() if k != "new_vulns"} for r in results]}


@app.post("/api/collect/{source_id}")
def api_collect_one(source_id: int, db: Session = Depends(get_db)):
    s = crud.get_source(db, source_id)
    if not s:
        raise HTTPException(404, "监控源不存在")
    r = collect_source(db, s)
    r.pop("new_vulns", None)
    return r


# ---------- 通知测试 ----------

@app.post("/api/test-dingtalk")
def api_test_dingtalk(db: Session = Depends(get_db)):
    """测试通知(兼容旧路径,默认钉钉通道)。"""
    return _do_test_notify(db)


@app.post("/api/test-notify")
def api_test_notify(db: Session = Depends(get_db)):
    """测试通知:按 notify_channel 配置路由到对应通道。"""
    return _do_test_notify(db)


def _do_test_notify(db: Session) -> dict:
    channel = crud.get_setting(db, "notify_channel", "dingtalk") or "dingtalk"
    cred_key, secret_key = CHANNEL_KEYS.get(channel, CHANNEL_KEYS["dingtalk"])
    credential = crud.get_setting(db, cred_key, "")
    secret = crud.get_setting(db, secret_key, "") if secret_key else ""
    if not credential:
        return {"ok": False, "msg": f"未配置 {channel} 的凭证({cred_key})"}
    ok = send(channel, credential, secret, "VulnWatch 测试", "这是一条来自 VulnWatch 的测试消息 ✅")
    return {"ok": ok, "channel": channel}


# ---------- 静态页面 ----------

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
