# VulnWatch 优化报告(v0.2.0)

本文档记录对 [minnana/vulnwatch](https://github.com/minnana/vulnwatch) 的一次完整代码审查与优化。
所有改动都已落地到本目录(与仓库同结构,可直接覆盖),并保持 **数据库结构不变、API 路径向后兼容** —— 已有 `data/vulnwatch.db` 可以直接继续用。

> ⚠️ 说明:本次优化在一个**无法执行命令**的环境中完成(没有 shell / Python 运行时),因此**没有实际运行过服务或测试**。
> 代码经过逐文件人工审查,请按文末「验证方法」在你机器上跑一遍再上线。这不是功能重构,而是缺陷修复 + 性能/可靠性/安全加固。

---

## 一、严重缺陷(会导致功能不符合预期)

### 1. NVD 请求间隔被重复叠加,每个请求约 12 秒

**原实现**:`app/collectors/nvd.py` 的 `NvdCpeCollector` 重写了 `_throttle()`(6 秒)和 `_http_get()`;
而基类 `BaseCollector._http_get()` 内部又会调用一次 `self._throttle()` —— 由于多态,`self._throttle` 是子类版本。
一次 HTTP 请求实际等待 **6 + 6 = 12 秒**,15 个 NVD 源每个源还要翻页,单次全量采集光是 NVD 就要 **3~5 分钟**,极易触发前端/代理超时。

**修复**:删除子类对 `_throttle/_http_get` 的重写,改为声明 `request_interval = config.NVD_REQUEST_INTERVAL`(基类统一处理),并配合下面的「NVD 批量模式」。

### 2. 15 个 NVD 源逐个查询 → 改为批量拉取一次

**原实现**:15 个默认源都是 `nvd_cpe` 类型,各自带一个关键词(Windows/Linux/MySQL……),每个源单独调一次 NVD API 并按关键词搜索。请求次数 = 源数量 × 页数。

**修复**:`NvdCpeCollector` 新增**批量模式**(`VULNWATCH_NVD_BULK=1`,默认开启):
1. 按 `pubStartDate/pubEndDate`(最近 `VULNWATCH_NVD_DAYS`,默认 7 天)翻页拉取全量 CVE(单页 2000 条);
2. 归一化时同时存一份「标题 + 描述 + 受影响 CPE」的小写文本作为检索串;
3. 每个 NVD 源在本地用 `keyword.lower() in haystack` 过滤,不再发请求;
4. 结果缓存 `VULNWATCH_NVD_CACHE_TTL`(默认 600 秒),同一次采集里多个源共享;
5. 批量失败自动降级为原来的「按关键词单查」模式,不影响可用性。
6. 显式配置了 `cpe` 的源仍走 `cpeName` 精确查询(批量数据无法保证 CPE 精确匹配)。

效果:NVD 相关请求从「15 源 × N 页」降到 **1~3 次**,且不再有 12 秒/请求的叠加等待。

### 3. 全局锁内 `sleep`,把不同域名的请求全部串行

**原实现**:`collectors/base.py` 的 `_throttle()` 在持有全局 `_rate_lock` 的情况下 `time.sleep(wait)`,一次只能有一个线程在等/发请求。
即使把采集改并行,所有域名(长亭、CISA、OSV、NVD……)也会被这把锁串成单车道。

**修复**:改为**预约式限速**(reservation):
```python
with _rate_lock:
    slot = max(now, last.get(host_interval_key, 0) + interval)
    last[key] = slot
sleep(max(0, slot - now))   # 锁外 sleep
```
锁内只做时间计算,不同域名可并行等待;同域名仍严格保持最小间隔。

### 4. 单条漏洞一次 `commit()` —— 一次采集约 2800 次事务

**原实现**:`crud.upsert_vulnerability()` 对每条漏洞执行 `db.commit(); db.refresh(obj)`。
CISA KEV 每次全量约 1300 条,加上 NVD/OSV 等,一次采集会产生 **~2800 次 fsync**,在机械盘/网络盘上能拖到分钟级,也是「采集慢」的主要原因之一。

**修复**:新增 `crud.upsert_many(db, source_id, items)`:
- 先一次性把该源已有记录读进内存(`unique_key → row`、`cve_id → row` 两个索引);
- 只在字段真的变化时才赋值(避免无意义的 UPDATE);
- 新对象 `db.add_all`,最后一次 `db.flush() + db.commit()`;
- 返回 `(新增数, 新漏洞 dict 列表)`,供推送逻辑使用,避免跨线程持有 ORM 对象。

单个源的采集事务数从「条数」降到 **1**。

### 5. 手动「立即采集」同步执行,前端/网关干等 3~5 分钟

**原实现**:`POST /api/collect` 在请求线程里同步跑完全部采集,Nginx/浏览器/钉钉代理常见 60 秒超时,页面会报错但后台其实还在跑;重复点击还会并发触发多次全量采集。

**修复**:
- `POST /api/collect` 立即返回 `{"started": true}`(已有任务在跑则返回 **409**),采集在守护线程中执行;
- 新增 `GET /api/collect/status`,返回 `running / started_at / finished_at / results / error`;
- 前端改为**轮询进度**,逐源显示「获取 N 条,新增 M 条」,按钮在运行期间禁用;
- 页面刷新后若任务仍在跑,会自动恢复进度显示;
- 全局 `begin_collection()/end_collection()` 互斥,定时任务与手动采集不会同时跑。

### 6. 推送报告不分条,超过通道上限直接失败

**原实现**:`build_report()` 一次生成 50 条漏洞的 markdown。钉钉 markdown 上限约 **20000 字节**、企微约 **4096 字节**,真实数据下经常超限,而发送函数把异常吞掉,只在 AlertLog 里记一条 failed,用户完全无感。

**修复**:新增 `notifier.build_report_messages(vulns, threshold, max_items=50)`:
- 按 `VULNWATCH_PUSH_MAX_BYTES`(默认 3600,取最严格通道)贪心分块;
- 每块都有标题和「第 i/N 部分」、KEV 段落仍置顶;
- `run_daily_job()` 循环发送**并检查每条返回值**,任一条失败即整体标记 failed(不再静默吞异常)。

### 7. 跨源去重可能丢掉 KEV(在野利用)记录

**原实现**:`_dedup_by_cve()` 按 `(严重程度, -CVSS)` 排序,同分时**按来源顺序**保留第一条 —— KEV 记录(CVSS 常为 None)可能在排序中输给 NVD 记录,导致「在野利用」标记和置顶高亮丢失。

**修复**:排序键改为 `(0 if is_kev else 1, 严重程度, -CVSS)`,**KEV 永远优先**;CVE 号统一大写后比较。

### 8. 静默时段/定时时间依赖服务器本地时区

**原实现**:`_is_silent_time()` 用 `datetime.now().time()`(进程本地时区)。Docker 镜像设了 `TZ=Asia/Shanghai`,但 systemd/裸机部署时服务器常是 UTC,静默时段会**错 8 小时**。

**修复**:统一用 `config.now_local()`(基于 `zoneinfo` 的 `VULNWATCH_TIMEZONE`,默认 `Asia/Shanghai`,缺 tzdata 时回退 UTC);`HH:MM` 解析抽成 `parse_hhmm()`,非法值不再抛异常。

### 9. 定时任务时间在网页里「能改但没用」

**原实现**:配置页有「每日汇总时间」输入框,保存进 `settings.daily_time`,但 `start_scheduler()` 只读环境变量 `VULNWATCH_DAILY_HOUR/_MINUTE` —— 改了不生效。

**修复**:`start_scheduler(db)` 优先读 `daily_time` 设置;新增 `reschedule_daily_job(db)`,`PUT /api/settings`(含批量保存)检测到 `daily_time` 变化时立即重排定时任务,无需重启。

### 10. 「首次采集建立基线、不推送」只写在 README,代码没实现

**原实现**:首轮采集会把最近 7 天的全部历史漏洞都当成新漏洞推出去,与文档描述相反。

**修复**:`run_daily_job()` 在采集前判断 `crud.count_vulnerabilities(db) == 0`,为空则只建基线,AlertLog 记 `baseline`,不推送。

### 11. AI 摘要是死代码,但 README 宣称可用

**原实现**:`summarize.py` 完整实现、`Vulnerability.ai_summary` 字段存在、前端/文档都宣称「填写 DeepSeek Key 可生成中文摘要」,但**没有任何地方调用** `summarize_vuln()`。

**修复**:`run_daily_job()` 在推送前,对将要推送的前 `VULNWATCH_AI_SUMMARY_LIMIT`(默认 5)条漏洞调用 DeepSeek 生成摘要,批量写回数据库,并展示在推送内容和网页列表中;未配置 Key 或调用失败时静默跳过,不影响主链路。

### 12. 存储型 XSS:CVE 号未转义

**原实现**:`static/index.html` 中 `"<b>${v.cve_id || '公告'}</b>"` 直接插值,而 `cve_id` 来自第三方源,可被构造成 `<img onerror=...>`。

**修复**:所有来自后端的字段统一走 `esc()`(并补上单引号转义);`safeLink()` 仍只允许 `http/https`。

---

## 二、性能优化

| 改动 | 原实现 | 现在 | 预期收益 |
|------|--------|------|----------|
| NVD 请求间隔 | 6s×2 = 12s/请求 | 6s/请求 | 单次采集 NVD 阶段快 2 倍以上 |
| NVD 查询次数 | 每源各查一次 | 批量 1~3 次 + 本地过滤 | 请求数降一个数量级 |
| 并发采集 | 全部串行 | 默认 8 线程(`COLLECT_WORKERS`) | 总耗时约降到 1/5~1/8 |
| 入库事务 | 每条一次 commit | 每源一次 commit | 事务数 ~2800 → ~28 |
| Go OSV 详情 | 串行 60 次 ×1s | 6 路并发 | 约 60s → 约 10s |
| 请求连接复用 | 每次 `requests.get` 新建连接 | 线程级 `requests.Session` | 减少 TLS 握手 |
| 漏洞列表 N+1 | 每行再查一次 `source` | `joinedload` 预加载 | 列表页查询 1+N → 1 |
| 仪表盘统计 | 前端 4 次请求、4 次 COUNT | 新增 `/api/stats` 单次聚合查询 | 首屏请求 4 → 1 |
| 配置保存 | 前端连续 15 次 PUT | 新增 `PUT /api/settings` 批量保存 | 15 请求 → 1 |
| SQLite | 默认 journal | WAL + busy_timeout 30s + foreign_keys | 读写并发不再 `database is locked` |

另外:`list_vulnerabilities` 的 `days` 语义保持原样(按「发布 或 首次发现」过滤),查询参数加了边界校验
(`days 1..365`、`limit 1..500`、`offset >= 0`、`severity` 枚举),避免 `limit=10^9` 这类请求打满内存。

---

## 三、健壮性 / 可观测性

- **AlertLog 全量记录**:原来只有「确实要推」时才写日志,静默/跳过/无凭证/首轮基线都查不到;现在每条路径都记录 `success / failed / silent / skipped / baseline`(含失败原因)。
- **单源失败不影响整体**:`collect_source()` 捕获异常并 `db.rollback()`,失败信息写入结果(原来异常会冒泡中断整个采集)。
- **采集互斥**:APScheduler(`max_instances=1, coalesce=True, misfire_grace_time=3600`)+ 手动采集全局锁,避免重复采集和写冲突。
- **推送通道校验**:`/api/test-notify` 与配置保存都会校验通道名,未知通道不再悄悄退回钉钉却用错凭证。
- **发送函数不再吞异常**:五种通道的失败都会 `logger.warning` 记录状态码/响应片段,排查「为什么没收到」不用再猜。
- **`/api/health`**:新增公开健康检查(数据库连通 + 版本 + 业务时间 + 是否在采集),Docker `HEALTHCHECK` 与外部监控可直接用。
- **时间默认值**:`datetime.utcnow()`(已废弃)统一替换为 `config.utcnow()`,保持 naive UTC 语义,不改历史数据。
- **HTTP 会话超时/重试**:统一走 `_request()`,超时 `VULNWATCH_REQUEST_TIMEOUT`、重试 `VULNWATCH_RETRY_TIMES`,NVD/OSV 的关键请求都有退避。

---

## 四、安全加固

| 问题 | 修复 |
|------|------|
| 安全响应头在 401 响应上缺失(中间件注册顺序反了) | 调整注册顺序,安全头包住所有响应;401 也带 CSP/X-Frame-Options 等 |
| Basic 认证比较整串 `"user:pass"` | 只比较口令部分,并保持 `secrets.compare_digest` 常量时间比较 |
| `?token=` 会出现在访问日志/Referer 中 | 前端首次从 URL 取到口令后立即 `history.replaceState` 去掉;接口仍兼容该方式 |
| 令牌比较大小写敏感问题 | Bearer 前缀改为大小写不敏感,兼容不同客户端 |
| 无 CORS/缓存策略 | API 响应 `Cache-Control: no-store`;CSP 增加 `frame-ancestors 'none'; base-uri 'self'` |
| CVE 号 XSS(见上文) | 全字段转义 |
| 健康检查需要认证会导致容器探活失败 | `/api/health` 明确免认证,其余 `/api/*` 全保护 |
| 依赖里混入未使用的包 | 移除 `pydantic-settings`、`python-multipart`、`jinja2`,减少攻击面;补 `tzdata` |

---

## 五、部署 / 运维

- **Dockerfile**:补 `tzdata`(原镜像直接 `ln -sf /usr/share/zoneinfo/...`,slim 镜像里可能不存在);加 `PYTHONUNBUFFERED`、`PYTHONDONTWRITEBYTECODE`、`PIP_NO_CACHE_DIR`;加 `HEALTHCHECK`;`CMD` 显式 `--workers 1 --proxy-headers`;注释说明「必须单进程」及 root 与 `./data` 挂载权限的关系。
- **docker-compose.yml**:删除已废弃的 `version: "3.8"`;补 `healthcheck`、`VULNWATCH_AUTH_TOKEN`(从 `.env` 注入)、`VULNWATCH_TIMEZONE`;`replicas: 1` 防止误扩容。
- **新增 `.dockerignore`**:避免把 `data/`、`.git`、`__pycache__` 打进镜像。
- **vulnwatch.service**:补 `TZ`/`PYTHONUNBUFFERED`/`VULNWATCH_TIMEZONE`、`EnvironmentFile=-/opt/vulnwatch/.env`(便于放口令)、`--workers 1 --proxy-headers`、`NoNewPrivileges`、`PrivateTmp`。
- **run.py**:`HOST/PORT` 从 `VULNWATCH_HOST` / `VULNWATCH_PORT` 读取,不再写死。
- **requirements.txt**:清理未使用依赖,补 `tzdata`;版本保持锁定。
- **.gitignore**:补充 `*.db`、`.pytest_cache/`、`Thumbs.db` 等。
- **新增 `/api/stats`、`/api/health`、`PUT /api/settings`,旧接口全部保留**。

---

## 六、已知限制(本次未改,建议后续)

1. `avd` / `venustech` 两个源依赖 Playwright,默认关闭;保持原样,需要时自行安装。
2. 仍为**单进程**架构(APScheduler + SQLite)。若要水平扩容,应先换成「独立采集 worker + 任务队列 + Postgres」,不是本次优化范围。
3. 第三方源 HTML 结构变化会导致解析为空,属于外部依赖风险;建议后续给每个源加「连续 N 次 0 条」告警。
4. `unique_key` 的生成逻辑保持各采集器原样,未做统一;跨源去重仍以 `cve_id` 为主键逻辑。
5. 未引入自动化测试(原仓库只有文档、无可执行测试)。建议下一步补 `pytest` + 接口级用例(可用 `TestClient` + 固定 JSON 的 mock 响应)。
6. 同一个 CVE 被多个源命中时按「源」分别入库(唯一约束是 `cve_id + source_id`),所以仪表盘总数会略高于真实漏洞数;推送前已按 CVE 去重,不影响告警。若希望统计口径为「去重漏洞数」,可把 `crud.stats` 的计数改成 `count(distinct coalesce(cve_id, unique_key))`。

---

## 七、验证方法(请在本机执行)

本环境没有可用的 shell/Python,以下步骤**未被执行过**,请在本地或 CI 中验证。

> 已附一个离线冒烟测试:`python scripts/smoke_test.py`(需先 `pip install -r requirements-dev.txt`)。它用临时数据目录和 FastAPI TestClient 覆盖模块导入、13 种采集器注册、全部 HTTP 接口、批量入库幂等与 `ai_summary` 保留、日报分片、调度辅助函数、参数校验,不访问外网,退出码 0 即全部通过。
>
> 项目目录上一级还提供了 `deploy_vulnwatch.ps1`(不随仓库提交):自动创建 venv、装依赖、跑冒烟测试,通过后可一键克隆仓库→同步文件→提交→推送 GitHub。

```bash
# 0. 离线冒烟测试(最快,不联网)
pip install -r requirements-dev.txt
python scripts/smoke_test.py

# 1. 语法检查(最快发现低级错误)
python -m compileall -q app run.py

# 2. 启动
python -m venv venv && source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
python run.py
# 浏览器打开 http://127.0.0.1:8000,首次会建库并写入 28 个默认源

# 3. 接口冒烟
curl -s http://127.0.0.1:8000/api/health
curl -s "http://127.0.0.1:8000/api/stats?days=7"
curl -s "http://127.0.0.1:8000/api/vulnerabilities?days=7&limit=5"
curl -s -X POST http://127.0.0.1:8000/api/collect          # 返回 {"started":true}
curl -s http://127.0.0.1:8000/api/collect/status           # 轮询直到 running=false

# 4. 验证访问口令(设置后页面/静态资源应仍可打开,仅数据接口 401)
VULNWATCH_AUTH_TOKEN=test123 python run.py
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/health   # 200(公开)
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/            # 200(页面公开)
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/settings # 401
curl -s -H 'Authorization: Bearer test123' http://127.0.0.1:8000/api/settings

# 5. 验证推送分条(可选):配置好钉钉后
curl -s -X POST http://127.0.0.1:8000/api/test-notify
```

建议重点回归:默认 28 源采集数量与优化前对比、钉钉推送内容与分条、配置页保存/测试消息、监控源增删改、静默时段与每日时间修改。

---

## 八、改动文件清单

| 文件 | 类型 | 要点 |
|------|------|------|
| `app/config.py` | 重写 | 业务时区、NVD/并行/推送/AI 参数、`utcnow()` |
| `app/database.py` | 重写 | WAL、busy_timeout、连接池 |
| `app/models.py` | 微调 | 默认值改用 `config.utcnow`(表结构不变) |
| `app/schemas.py` | 扩展 | URL 校验、`StatsOut`、`VulnerabilityListOut`、`SettingsUpdate`、`CollectStatusOut` |
| `app/crud.py` | 重写 | 批量 upsert、stats、joinedload、批量配置/AI 摘要 |
| `app/collectors/base.py` | 重写 | 预约式限速、线程级 Session、统一重试 |
| `app/collectors/nvd.py` | 重写 | 批量模式、去掉双重限速 |
| `app/collectors/go_osv.py` | 微调 | 详情并发 |
| `app/collectors/oscs.py` | 微调 | 发布时间修正为 UTC |
| `app/collectors/html.py` | 微调 | 公告真实链接提取 |
| `app/collectors/*.py`(其余 9 个) | 微调 | 见第九节:补 `unique_key`、空字段/URL 兜底、等级映射、时区 |
| `app/notifier.py` | 重写 | 分条报告、失败日志、AI 摘要行 |
| `app/scheduler.py` | 重写 | 并行采集、KEV 去重、基线、AlertLog、可改时间 |
| `app/summarize.py` | 微调 | 接入配置、错误处理 |
| `app/main.py` | 重写 | lifespan、后台采集+状态、`/api/stats`、`/api/health`、批量配置、安全头顺序 |
| `static/index.html` | 重写 | 轮询进度、单次统计、批量保存、XSS 修复、token 引导 |
| `Dockerfile` / `docker-compose.yml` / `vulnwatch.service` / `run.py` / `requirements.txt` / `.gitignore` | 修改 | 部署与依赖修正 |
| `.dockerignore`、`OPTIMIZATION.md` | 新增 | 构建上下文与本文档 |
| `scripts/smoke_test.py`、`requirements-dev.txt` | 新增 | 离线冒烟测试(临时库 + TestClient)及其测试依赖 `httpx` |

## 九、二次审查修复（上线前自查发现）

在第一轮重写后，又做了一轮独立的交叉审查（静态检查全部文件、前后端接口契约、与新版 `base.py` 的兼容性），修掉了以下问题：

| 问题 | 位置 | 修复 |
|------|------|------|
| 非 CVE 的 RSS/公告条目没有 `unique_key`，每轮采集都会重复插入 | `app/collectors/rss.py` | 用 `entry.id/guid/link`，兜底对 `title+link` 取 sha1，作为稳定 `unique_key` |
| CISA KEV 未给 `unique_key`，仅靠 cveID 兜底 | `app/collectors/cisa_kev.py` | 显式写入 `unique_key = cve_id` |
| Seebug 在无编号无 CVE 时生成 `SSV-None`，多条公告被合并 | `app/collectors/seebug.py` | 退回公告链接作为 key |
| 奇安信 `tag` 字段可能为 null 导致 TypeError | `app/collectors/qianxin_ti.py` | `d.get("tag") or []` |
| 微步缺 id 时 URL 变成 `/vul/None`；仍用 `datetime.utcnow()` | `app/collectors/threatbook.py` | 缺 id 时回退情报首页；改用 `config.utcnow()` |
| 启明星辰等级映射缺「严重/紧急」，CRITICAL 分支不可达 | `app/collectors/venustech.py` | 补 `严重/紧急 → CRITICAL` |
| 重新采集会把已生成的 AI 摘要清空（采集数据 `ai_summary=None` 覆盖旧值） | `app/crud.py` `upsert_many` | 更新时跳过 `ai_summary is None` |
| 口令含中文时 `secrets.compare_digest` 抛 TypeError，所有请求 500 | `app/main.py` `_check_token` | 比较前统一 `.encode("utf-8")` |
| OSCS 详情接口对未知等级返回 `UNKNOWN`，把列表页已判定的 HIGH/CRITICAL 降级丢弃 | `app/collectors/oscs.py` | 仅当详情等级为 HIGH/CRITICAL 时才覆盖 |
| `VULNWATCH_NVD_BULK` 配置读取后从未使用（文档里的开关是空操作） | `app/collectors/nvd.py` | 关闭时退化为按关键词查询 |
| Pydantic 旧式 `class Config` 已弃用 | `app/schemas.py` | 改为 `model_config = ConfigDict(from_attributes=True)` |
| 重试配置异常时 `raise None` 会变成 TypeError | `app/collectors/base.py` | 显式抛 `RuntimeError` 兜底 |
| `_extract_token` 有无用的 no-op 赋值 | `app/main.py` | 删除 |
| `base.py` 自己重复解析 `RETRY_TIMES` | `app/collectors/base.py` | 统一用 `config.RETRY_TIMES` 并去掉冗余 import |
| 设置口令后，页面/静态资源也被拦，`<script>` 无法带 Authorization 头 → 页面 401 | `app/main.py` `_is_public_path` | 放行 `/`、`/static/*`、`/favicon.ico`、`/api/health`，数据接口仍鉴权 |
| 每日时间输入框留空时，整批配置保存 + 发送测试全部 400 | `app/main.py` 批量设置 + `static/index.html` | 后端：空 `daily_time` 跳过该项；前端：空值不提交 |
| 新增监控源会沿用上一次编辑的类别/类型 | `static/index.html` `showSourceForm()` | 重置 `#s-category`、`#s-type` |
| 采集状态轮询失败时界面停在「采集中」，看起来像卡死 | `static/index.html` `pollCollectStatus()` | 显示失败原因并 toast |
| 遇到 409（定时任务正在采集）不显示进度 | `static/index.html` `doCollectAll()` | 自动切换到轮询模式 |
| CVSS 列直接插值（类型为 Float，当前安全，但保留兜底） | `static/index.html` | 改为 `esc(v.cvss_score ?? '-')` |
| Docker 构建可能被 tzdata 的 debconf 卡住 | `Dockerfile` | `ARG DEBIAN_FRONTEND=noninteractive` |
| 部署缺少可复制的环境变量模板 | `.env.example`（新增） | 口令/时区/数据目录/定时时间示例；README 引用 |
| 页面公开后文档未同步 | `README.md` | 安全说明、环境变量表（重试/NVD 缓存/OSV 并发）、`.env.example` 用法 |

> 说明：本环境没有可用的 shell / Python 解释器（命令工具无输出），以上改动全部为静态审查与人工核对，**未实际运行**。请按第七节的验证命令在本地或服务器上跑一遍。真实环境中仍建议优先看 `app/collectors/*.py` 与 `app/scheduler.py` 的日志输出。

