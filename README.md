# VulnWatch · 漏洞情报监控系统

> **Vuln**（漏洞）+ **Watch**（守望）= 帮你 24 小时盯着服务器、数据库、办公软件有没有新漏洞，一有新漏洞就自动发消息提醒你。

一个**零门槛、开箱即用**的安全公告监控工具。它每天自动去各大官方渠道（微软、NVD、CISA、Go、群晖……）和国内安全社区（长亭、奇安信、微步、Seebug……）抓最新的漏洞情报，按严重程度打分，然后把你该关心的**高危漏洞**自动推送到钉钉群，其他的一律存起来，随时在网页上翻看。

---

## 一句话说清楚它是干嘛的

> 你公司有 200 台电脑、6 台服务器、一堆数据库和中间件，你不可能天天自己去翻各个厂商的安全公告。**VulnWatch 替你做这件事**——每天自动搜一遍，发现新的高危漏洞就喊你。

---

## 它解决了什么痛点？

| 你现在的痛 | VulnWatch 怎么解决 |
|-----------|-------------------|
| 😩 漏洞公告散落在十几个网站，没空天天看 | 自动聚合 **28 个官方/社区源**，一个网页看全部 |
| 😱 等知道漏洞时，可能已经被打了 | **每天定时采集**，当天新出的漏洞当天推送 |
| 😵 不知道哪些漏洞该优先处理 | 按 **CVSS 评分 + 是否在野利用** 自动分级，严重的置顶 |
| 🤯 国外 CVE 库不覆盖国产软件（OA、财务、国产数据库） | 接入**国内安全社区源**，国产软件漏洞也盯得住 |
| 📱 不在电脑前就错过告警 | 自动推送到**钉钉群**（企微/飞书/Server酱/PushPlus 也可切换） |
| 🔁 同一个漏洞被多个源重复报，烦 | **跨源去重**，同一个 CVE 只推一次（优先保留 KEV 记录） |

---

## 核心功能

### 1. 多源自动采集（28 个源）

| 类别 | 监控对象 | 数据来源 |
|------|----------|----------|
| 🖥️ 操作系统 | Windows Server / Linux 内核 | NVD + MSRC |
| 💾 数据库 | MySQL / PostgreSQL / SQL Server / Redis / MongoDB / Oracle | NVD |
| 🌐 Web 服务器 | IIS / Nginx / Apache / Struts2 | NVD + 厂商公告 |
| 📦 NAS | 群晖 DSM / QNAP | 厂商公告页 |
| 🖧 虚拟化 | VMware ESXi / vCenter | NVD |
| 🔧 语言运行时 | Go / Node.js / Python / OpenJDK | Go OSV + NVD |
| 🚨 在野利用 | CISA KEV（正被攻击的漏洞） | CISA 官方 |
| 🇨🇳 国内情报 | 长亭 / OSCS / 奇安信 / 微步 / Seebug / Struts2 | 官方 API |
| 🇨🇳 国内情报(可选) | 阿里云 AVD / 启明星辰 | 需装 Playwright |

> 国内源借鉴了开源项目 [watchvuln](https://github.com/zema1/watchvuln) 的采集思路，专门补足「国外 NVD 覆盖不到的国产软件漏洞」。

采集性能（v0.2.0 起）：

- **NVD 批量模式**：15 个 NVD 源不再各查一次，而是按时间范围一次拉全量、本地按关键词过滤，请求数从 15 次降到 1~3 次；
- **多源并行采集**：默认 8 个线程并发（`VULNWATCH_COLLECT_WORKERS` 可调）；
- **批量入库**：一次采集只提交一次事务，而不是一条漏洞一次 commit；
- **手动采集改为后台任务**：页面立即返回、实时显示每个源的进度，不会因为代理超时白等。

### 2. 智能分级 + 精准推送

- 按 **CVSS 评分**分成 5 档：严重 / 高危 / 中危 / 低危 / 未知
- **在野利用（KEV）漏洞无条件置顶**，🚨 高亮，且跨源去重时优先保留 KEV 记录
- 支持**产品关键词黑白名单**——只看你公司真正在用的产品，其他全过滤掉
- 支持**标签过滤**——只看带「POC公开」「预警」等标记的，精准命中
- **跨源去重**——同一个 CVE 从多个源抓到，只推最严重（KEV 优先）的那一条
- **静默时段**——可设置凌晨 00:00-07:00 不打扰（按业务时区判断，不是服务器时区）
- **首次采集不轰炸**——数据库为空时只建基线、不推送，与文档描述一致
- **超长报告自动分条**——钉钉 2 万字节 / 企微 4096 字节限制都不会截断内容

### 3. 多渠道通知

- ✅ **钉钉机器人**（默认，支持加签，最常用）
- ✅ **企业微信 / 飞书 / Server酱 / PushPlus**，在配置页切换即可，无需改代码
- 每次推送（成功/失败/静默/跳过/基线）都会记一条 AlertLog，排查问题有据可查

### 4. Web 管理界面

网页上就能完成所有操作，不用碰命令行：
- 查看漏洞列表、按等级/关键词/KEV/时间筛选，展示 AI 摘要
- 增删改监控源
- 配置通知渠道、阈值、黑白名单、静默时段、每日推送时间（保存即生效，无需重启）
- 手动触发「立即采集」（后台执行 + 实时进度）
- 一键「发送测试消息」验证推送是否通

### 5. 安全加固

- 可选**访问口令**（`VULNWATCH_AUTH_TOKEN`），支持 `Authorization: Bearer`、HTTP Basic、`?token=` 三种方式
- 访问口令可放在 URL 里首次打开（`http://ip:8000/?token=xxx`），页面会自动存入 localStorage 并从地址栏抹掉
- 内置安全响应头（CSP / X-Frame-Options / nosniff 等），401 响应同样带安全头
- 所有列表渲染对 CVE 号、标题、来源等字段做 HTML 转义（防存储型 XSS）
- `/api/health`、页面和 `/static/*` 静态资源公开（页面本身不含数据，浏览器加载脚本也无法附带头）；其余数据接口在设置口令后一律需要认证
- 口令保存在 localStorage 中，刷新页面或收藏地址都不会失效
- API 数据响应带 `Cache-Control: no-store`，避免共享终端缓存

---

## 快速开始（本地试用，2 分钟）

```bash
# 1. 创建虚拟环境（隔离依赖，避免污染系统）
python -m venv venv
source venv/bin/activate        # Windows 用：venv\Scripts\activate

# 2. 安装依赖
pip install -r requirements.txt

# 3. 启动（首次运行会自动建数据库 + 内置 28 个默认源）
python run.py
```

浏览器打开 **http://127.0.0.1:8000**，就能看到管理界面了。

> 第一次打开时漏洞列表可能是空的，点一下「立即采集」按钮，任务会在后台跑，页面上能看到每个源的进度；首轮只建历史基线不推送。

> Windows 上如果启动报 `ZoneInfoNotFoundError`，`pip install tzdata` 即可（requirements.txt 已包含）。

### 想先自检一遍？（可选）

项目自带离线冒烟测试（不访问任何外部网站，约 10 秒）：

```bash
pip install -r requirements-dev.txt   # 额外的测试依赖（httpx）
python scripts/smoke_test.py
```

它会检查：模块导入、13 种采集器注册、全部 HTTP 接口（健康检查 / 监控源增删改查 / 漏洞列表 / 统计 / 配置读写）、批量入库幂等与 AI 摘要保留、日报分片、调度辅助函数、参数校验。退出码 `0` 表示全部通过。

---

## 部署到服务器（正式使用）

完整教程见 **[DEPLOY.md](DEPLOY.md)**，这里给最常用的两条路：

> ⚠️ **必须以单进程（单 worker）运行**：APScheduler 和 SQLite 都在进程内。多 worker 会导致定时任务被重复注册、SQLite 锁竞争。Dockerfile / systemd / compose 里都已固定 `--workers 1`。

### 方式一：Docker（推荐，最省心）

```bash
# 上传代码到服务器后
cd /opt/vulnwatch
export VULNWATCH_AUTH_TOKEN=$(openssl rand -hex 16)   # 建议设置访问口令
docker compose up -d --build                          # 构建并后台启动
docker compose logs -f vulnwatch                      # 看日志
```

浏览器打开 `http://服务器IP:8000`。容器内置 healthcheck（调用 `/api/health`），`docker ps` 可直接看到健康状态。

> 首次部署可先 `cp .env.example .env`，按注释填写访问口令、时区等；compose 会自动读取 `.env`，无需 `export`。

### 方式二：systemd（开机自启 + 长期运行）

```bash
cd /opt/vulnwatch
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 敏感配置（访问口令等）放 .env，service 已配置 EnvironmentFile
echo "VULNWATCH_AUTH_TOKEN=$(openssl rand -hex 16)" | sudo tee /opt/vulnwatch/.env

sudo cp vulnwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vulnwatch
```

---

## 配置说明

### 环境变量（进程级，改完需重启）

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `VULNWATCH_AUTH_TOKEN` | 空 | 访问口令；留空=匿名访问 |
| `VULNWATCH_DATA_DIR` | `./data` | 数据目录（SQLite 与备份） |
| `VULNWATCH_DB` | `data/vulnwatch.db` | 数据库文件路径 |
| `VULNWATCH_TIMEZONE` | `Asia/Shanghai` | 业务时区（定时任务/静默/报告时间） |
| `VULNWATCH_DAILY_HOUR` / `_MINUTE` | `9` / `0` | 每日采集+推送时间（网页里改 `daily_time` 会覆盖它） |
| `VULNWATCH_COLLECT_WORKERS` | `8` | 并行采集线程数，慢网可降到 2~4 |
| `VULNWATCH_REQUEST_INTERVAL` | `1.0` | 同一域名请求最小间隔（秒） |
| `VULNWATCH_RETRY_TIMES` | `2` | 单次请求网络失败的重试次数 |
| `VULNWATCH_NVD_BULK` | `1` | NVD 批量模式开关（一次拉取最近 N 天全量，供所有 NVD 源本地过滤） |
| `VULNWATCH_NVD_DAYS` | `7` | NVD 批量拉取最近天数 |
| `VULNWATCH_NVD_INTERVAL` | `6.0` | NVD 请求间隔（官方无 key 建议 ≥6 秒） |
| `VULNWATCH_NVD_CACHE_TTL` | `600` | NVD 批量结果进程内缓存秒数 |
| `VULNWATCH_OSV_CONCURRENCY` | `6` | Go 官方漏洞库详情并发数 |
| `VULNWATCH_PUSH_MAX_BYTES` | `3600` | 单条消息字节上限（超长自动分条） |
| `VULNWATCH_AI_MODEL` / `_AI_SUMMARY_LIMIT` | `deepseek-chat` / `5` | DeepSeek 摘要模型与条数上限 |

### 配置页（存数据库，保存即生效）

第一步：配置钉钉推送

1. 打开钉钉群 → 右上角「群设置」→「智能群助手」→「添加机器人」→「自定义机器人」
2. 安全设置选 **「加签」**（最稳妥，不用设关键词），记下 **Webhook 地址** 和 **加签密钥(Secret)**
3. 打开 VulnWatch 网页 →「配置」→ 填入这两项 → 点「发送测试消息」，钉钉群收到消息就成功了 ✅

第二步：设置推送阈值

在「配置」页选推送等级，默认「高危及以上」：
- **仅严重**：只推最紧急的
- **高危及以上**（推荐）：严重 + 高危
- **中危及以上 / 全部**：推得更多，也更吵

> 不管阈值设多高，**在野利用漏洞（KEV）永远会推**，因为那是正在被攻击的。

第三步（强烈建议）：设置访问口令

部署到公网或多人环境前，务必设一个访问口令，防止别人看到你的监控数据：

```bash
# Docker：用 .env 文件（docker compose 会自动读取）
echo "VULNWATCH_AUTH_TOKEN=你的随机口令" > .env

# systemd：写 /opt/vulnwatch/.env（service 已配置 EnvironmentFile）
```

口令建议用 `openssl rand -hex 16` 生成一段随机串。设置后首次访问用 `http://服务器IP:8000/?token=口令` 打开即可。

第四步（可选）：只关心自己公司的产品

在「配置」页填**产品关键词白名单**（逗号分隔），比如：

```
nginx, redis, 群晖, VMware, mysql
```

填了之后，只推标题/受影响产品里命中这些关键词的漏洞，其他全部忽略，推送瞬间变干净。

第五步（可选）：每日推送时间

「配置」页「定时任务」里改 `每日汇总时间`（HH:MM），保存后**立即生效**，不需要重启。

---

## 日常维护教程

### 每天要做的事

**什么都不用做。** 系统每天 09:00（可改）自动采集 + 推送，你只需要看钉钉。

### 每周/偶尔看一眼

| 事项 | 操作 |
|------|------|
| 看有没有采集失败的源 | 网页「监控源」页，点「采集」单独重试 |
| 备份数据库 | 复制 `data/` 目录即可（见下方命令） |
| 更新系统 | `git pull` + `pip install -r requirements.txt` + 重启 |

### 备份与恢复

```bash
# 备份（数据库就是 data/ 目录里的一个文件）
tar -czf vulnwatch-backup-$(date +%F).tar.gz data/

# 恢复（解压回去即可）
tar -xzf vulnwatch-backup-2026-11-11.tar.gz
```

> SQLite 已开启 WAL 模式，运行中直接复制 `data/` 目录也能拿到一致快照；更稳妥的做法是先停服务。

### 常见问题

**Q: 某个源一直采集到 0 条？**
A: 大概率是那款产品近期真没新漏洞，或关键词太窄。去「监控源」页调关键词后点「采集」单独重试。

**Q: 首次部署推了一大堆历史漏洞？**
A: 不会。数据库为空时首轮采集只建立历史基线、不推送，之后每天**只推新增**的漏洞。

**Q: 想改每天推送的时间？**
A: 直接去「配置」→「定时任务」改每天时间，保存即生效；也可以用环境变量 `VULNWATCH_DAILY_HOUR` / `VULNWATCH_DAILY_MINUTE`（仅当数据库里没有 `daily_time` 时生效）。

**Q: 钉钉/企微提示消息太长发送失败？**
A: 已经按 `VULNWATCH_PUSH_MAX_BYTES`（默认 3600 字节）自动分条；如仍失败可再调小。

**Q: 采集很慢？**
A: 默认并行 8 个源 + NVD 批量模式，正常 10~60 秒。慢网环境把 `VULNWATCH_COLLECT_WORKERS` 调到 2~4，并适当加大 `VULNWATCH_NVD_INTERVAL`。

---

## 目录结构

```
.
├── app/
│   ├── main.py              # FastAPI 入口 + 页面 + 接口
│   ├── config.py            # 配置（环境变量 + 时区工具）
│   ├── database.py          # 数据库连接（WAL/连接池）
│   ├── models.py            # 数据模型
│   ├── schemas.py           # 请求/响应校验
│   ├── crud.py              # 数据库读写（批量 upsert）
│   ├── collectors/          # 采集器（13 类，对应 28 个源）
│   ├── notifier.py          # 多通道通知 + 分条报告
│   ├── scheduler.py         # 定时任务 + 过滤推送逻辑
│   └── summarize.py         # DeepSeek 可选摘要
├── static/index.html        # Web 管理界面
├── requirements.txt
├── run.py                   # 启动入口
├── Dockerfile
├── docker-compose.yml
├── vulnwatch.service        # systemd 服务文件
├── OPTIMIZATION.md          # 本次优化清单与验证方法
└── README.md
```

---

## 本次优化（v0.2.0）

详见 **[OPTIMIZATION.md](OPTIMIZATION.md)**。一句话总结：

- 修复 NVD 请求间隔被重复叠加（每请求约 12 秒）的问题，并改为批量拉取；
- 修复全局锁内 sleep 导致所有域名串行的问题；
- 单条漏洞 commit → 批量 upsert（一次采集的事务数从 ~2800 降到 1）；
- Go OSV 详情从串行 60 次请求改为 6 路并发；
- 手动采集改为后台任务 + 进度轮询，解决同步阻塞/网关超时；
- 报告按通道字节上限自动分条，超长不再被截断；
- 静默时段/定时任务改用业务时区，不再依赖服务器本地时间；
- 跨源去重优先保留 KEV 记录（原来可能丢掉在野利用标记）；
- 首次采集建立基线不推送、AlertLog 全量记录，与文档行为一致；
- 修复漏洞列表 CVE 号未转义的存储型 XSS；
- 修复安全响应头在 401 响应上缺失、Docker 镜像缺 tzdata、compose 废弃 version 字段等问题；
- 补齐 README 中宣称但未落地的能力（AI 摘要、基线、daily_time 网页可改）。

---

## 给 AI 的一键搭建指令

如果你想用任意 AI 助手（ChatGPT、Claude、WorkBuddy、豆包、Kimi 等）帮你一键搭建，直接把下面这段话复制给它：

```text
帮我部署 GitHub 上的 minnana/vulnwatch 这个漏洞监控项目，要求：

1. 环境：Ubuntu 22.04（或告诉我你现在的系统）
2. 用 Docker 方式部署（docker compose up -d --build）
3. 部署到 /opt/vulnwatch 目录
4. 启动后告诉我访问地址（默认 http://服务器IP:8000）
5. 设置访问口令 VULNWATCH_AUTH_TOKEN（帮我生成一个随机口令并告诉我）
6. 最后教我三步：怎么配钉钉机器人、怎么设推送阈值、怎么备份数据库

请一步步来，每步都给我能直接复制粘贴的命令。
```

这段指令已经包含：环境、部署方式、目录、端口、安全口令、后续配置指引，AI 照着做即可，几乎不需要你再补充什么。

---

## 技术栈

- **后端**：Python 3.10+ / FastAPI / SQLAlchemy / SQLite
- **任务调度**：APScheduler（进程内单实例）
- **前端**：原生 HTML/JS 单页（无框架，轻量）
- **通知**：钉钉 / 企微 / 飞书 / Server酱 / PushPlus

---

## License

开源，仅供企业内部安全监控使用。采集数据版权归各数据源所有，请遵守各源的使用条款。
