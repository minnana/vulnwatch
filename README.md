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
| 📱 不在电脑前就错过告警 | 自动推送到**钉钉群**（也预留了企微/飞书等） |
| 🔁 同一个漏洞被多个源重复报，烦 | **跨源去重**，同一个 CVE 只推一次 |

---

## 核心功能

### 1. 多源自动采集（28 个源）

| 类别 | 监控对象 | 数据来源 |
|------|----------|----------|
| 🖥️ 操作系统 | Windows Server / Linux 内核 | NVD + MSRC |
| 💾 数据库 | MySQL / PostgreSQL / SQL Server / Redis / MongoDB / Oracle | NVD |
| 🌐 Web 服务器 | IIS / Nginx / Apache | NVD + 厂商公告 |
| 📦 NAS | 群晖 DSM / QNAP | 厂商公告页 |
| 🖧 虚拟化 | VMware ESXi / vCenter | NVD |
| 🔧 语言运行时 | Go / Node.js / Python / OpenJDK | Go OSV + NVD |
| 🚨 在野利用 | CISA KEV（正被攻击的漏洞） | CISA 官方 |
| 🇨🇳 国内情报 | 长亭 / OSCS / 奇安信 / 微步 / Seebug / Struts2 | 官方 API |
| 🇨🇳 国内情报(可选) | 阿里云 AVD / 启明星辰 | 需装 Playwright |

> 国内源借鉴了开源项目 [watchvuln](https://github.com/zema1/watchvuln) 的采集思路，专门补足「国外 NVD 覆盖不到的国产软件漏洞」。

### 2. 智能分级 + 精准推送

- 按 **CVSS 评分**分成 5 档：严重 / 高危 / 中危 / 低危 / 未知
- **在野利用（KEV）漏洞无条件置顶**，🚨 高亮
- 支持**产品关键词黑白名单**——只看你公司真正在用的产品，其他全过滤掉
- 支持**标签过滤**——只看带「POC公开」「预警」等标记的，精准命中
- **跨源去重**——同一个 CVE 从多个源抓到，只推最严重的那一条
- **静默时段**——可设置凌晨 00:00-07:00 不打扰

### 3. 多渠道通知

- ✅ **钉钉机器人**（默认，支持加签，最常用）
- ✅ 预留 **企业微信 / 飞书 / Server酱 / PushPlus** 接口，改个配置就能切

### 4. Web 管理界面

网页上就能完成所有操作，不用碰命令行：
- 查看漏洞列表、按等级筛选
- 增删改监控源
- 配置通知渠道、阈值、黑白名单
- 手动触发「立即采集」
- 一键「发送测试消息」验证推送是否通

### 5. 安全加固

- 可选**访问口令**（`VULNWATCH_AUTH_TOKEN`），防止外人访问你的监控数据
- 内置安全响应头，防 XSS

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

> 第一次打开时漏洞列表可能是空的，点一下「立即采集」按钮，等一两分钟数据就进来了。

---

## 部署到服务器（正式使用）

完整教程见 **[DEPLOY.md](DEPLOY.md)**，这里给最常用的两条路：

### 方式一：Docker（推荐，最省心）

```bash
# 上传代码到服务器后
cd /opt/vulnwatch
docker compose up -d --build      # 构建并后台启动
docker compose logs -f vulnwatch  # 看日志
```

浏览器打开 `http://服务器IP:8000`。

### 方式二：systemd（开机自启 + 长期运行）

```bash
cd /opt/vulnwatch
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

sudo cp vulnwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vulnwatch
```

---

## 配置教程（小白版）

### 第一步：配置钉钉推送

1. 打开钉钉群 → 右上角「群设置」→「智能群助手」→「添加机器人」→「自定义机器人」
2. 安全设置选 **「加签」**（最稳妥，不用设关键词），记下 **Webhook 地址** 和 **加签密钥(Secret)**
3. 打开 VulnWatch 网页 →「配置」→ 填入这两项 → 点「发送测试消息」，钉钉群收到消息就成功了 ✅

### 第二步：设置推送阈值

在「配置」页选推送等级，默认「高危及以上」：
- **仅严重**：只推最紧急的
- **高危及以上**（推荐）：严重 + 高危
- **中危及以上 / 全部**：推得更多，也更吵

> 不管阈值设多高，**在野利用漏洞（KEV）永远会推**，因为那是正在被攻击的。

### 第三步（强烈建议）：设置访问口令

部署到公网或多人环境前，务必设一个访问口令，防止别人看到你的监控数据：

```bash
# Docker：在 docker-compose.yml 的 environment 里加
VULNWATCH_AUTH_TOKEN=你的随机口令

# systemd：在 vulnwatch.service 的 Environment 里加
Environment=VULNWATCH_AUTH_TOKEN=你的随机口令
```

口令建议用 `openssl rand -hex 16` 生成一段随机串。

### 第四步（可选）：只关心自己公司的产品

在「配置」页填**产品关键词白名单**（逗号分隔），比如：

```
nginx, redis, 群晖, VMware, mysql
```

填了之后，只推标题/受影响产品里命中这些关键词的漏洞，其他全部忽略，推送瞬间变干净。

---

## 日常维护教程

### 每天要做的事

**什么都不用做。** 系统每天 09:00 自动采集 + 推送，你只需要看钉钉。

### 每周/偶尔看一眼

| 事项 | 操作 |
|------|------|
| 看有没有采集失败的源 | 网页「监控源」页，观察各源状态 |
| 备份数据库 | 复制 `data/` 目录即可（见下方命令） |
| 更新系统 | `git pull` + `pip install -r requirements.txt` + 重启 |

### 备份与恢复

```bash
# 备份（数据库就是 data/ 目录里的一个文件）
tar -czf vulnwatch-backup-$(date +%F).tar.gz data/

# 恢复（解压回去即可）
tar -xzf vulnwatch-backup-2026-11-11.tar.gz
```

### 常见问题

**Q: 某个源一直采集到 0 条？**
A: 大概率是那款产品近期真没新漏洞，或关键词太窄。去「监控源」页调关键词后点「采集」单独重试。

**Q: 首次部署推了一大堆历史漏洞？**
A: 正常。首次采集会建立历史基线，之后每天**只推新增**的漏洞，不会重复轰炸。

**Q: 想改每天推送的时间？**
A: 设环境变量 `VULNWATCH_DAILY_HOUR`（默认 9）和 `VULNWATCH_DAILY_MINUTE`（默认 0），重启生效。

---

## 目录结构

```
.
├── app/
│   ├── main.py              # FastAPI 入口 + 页面 + 接口
│   ├── config.py            # 配置
│   ├── database.py          # 数据库连接
│   ├── models.py            # 数据模型
│   ├── schemas.py           # 请求/响应校验
│   ├── crud.py              # 数据库读写
│   ├── collectors/          # 采集器（13 类，对应 28 个源）
│   ├── notifier.py          # 多通道通知（钉钉/企微/飞书/Server酱/PushPlus）
│   ├── scheduler.py         # 定时任务 + 过滤推送逻辑
│   └── summarize.py         # DeepSeek 可选摘要
├── static/index.html        # Web 管理界面
├── requirements.txt
├── run.py                   # 启动入口
├── Dockerfile
├── docker-compose.yml
├── vulnwatch.service        # systemd 服务文件
└── README.md
```

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
- **任务调度**：APScheduler
- **前端**：原生 HTML/JS 单页（无框架，轻量）
- **通知**：钉钉 / 企微 / 飞书 / Server酱 / PushPlus

---

## License

开源，仅供企业内部安全监控使用。采集数据版权归各数据源所有，请遵守各源的使用条款。
