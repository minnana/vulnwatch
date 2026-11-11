# 漏洞情报监控系统 (VulnWatch)

监控 Windows Server / Linux / 群晖 NAS / VMware ESXi / IIS / 各类数据库 / Go / Nginx 等
系统与应用的**官方或第三方安全公告、补丁公告**,每日汇总,重要漏洞高亮,并推送钉钉机器人。

## 核心特性

- **多源采集**:NVD CVE API 2.0(主源)、CISA KEV(在野利用)、厂商公告页/RSS(Synology、VMware、Microsoft 等)
- **统一归一化**:按 CVE 编号去重,统一字段(CVE、标题、严重等级、CVSS 评分、受影响产品、链接、发布日期)
- **分级高亮**:按 CVSS 评分 + 是否在野利用(KEV)自动分级 Critical / High / Medium / Low
- **钉钉推送**:重要漏洞(可配置阈值)自动推送到钉钉机器人(支持加签)
- **定时任务**:APScheduler 每日定时汇总(可配置时间)
- **Web 管理界面**:配置监控源、钉钉机器人、告警阈值、查看漏洞列表、手动触发采集
- **DeepSeek 可选增强**:用 AI 生成中文摘要(默认关闭,不影响主链路)

## 目录结构

```
.
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI 入口 + 静态页面 + 定时任务
│   ├── config.py            # 配置管理(settings)
│   ├── database.py          # SQLAlchemy 引擎 + Session
│   ├── models.py            # 数据模型
│   ├── schemas.py           # Pydantic 请求/响应模型
│   ├── crud.py              # 数据库读写
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base.py          # 采集器基类
│   │   ├── nvd.py           # NVD CVE API 采集器
│   │   ├── cisa_kev.py      # CISA KEV 采集器
│   │   ├── rss.py           # 通用 RSS/厂商公告采集器
│   │   ├── html.py          # HTML 公告页解析
│   │   ├── go_osv.py        # Go 官方漏洞库
│   │   ├── chaitin.py       # 长亭漏洞库
│   │   ├── oscs.py          # OSCS 开源安全情报
│   │   ├── qianxin_ti.py    # 奇安信威胁情报
│   │   ├── threatbook.py    # 微步在线
│   │   ├── seebug.py        # 知道创宇 Seebug
│   │   ├── struts2.py       # Apache Struts2
│   │   ├── avd.py           # 阿里云漏洞库(需 Playwright)
│   │   └── venustech.py     # 启明星辰(需 Playwright)
│   ├── notifier.py          # 钉钉推送
│   ├── summarize.py         # DeepSeek 可选摘要
│   └── scheduler.py         # 定时任务
├── static/
│   └── index.html           # Web 管理界面
├── requirements.txt
├── run.py                   # 启动入口
└── README.md
```

## 快速开始

```bash
# 1. 创建虚拟环境
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# 2. 安装依赖
pip install -r requirements.txt

# 3. 启动(首次运行自动建库 + 内置默认监控源)
python run.py
# 或
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

访问 http://127.0.0.1:8000 打开 Web 管理界面。

## 配置说明

系统配置存储在 `data/vulnwatch.db`(SQLite),通过 Web 界面或环境变量配置。

### 钉钉机器人

1. 钉钉群 → 群设置 → 智能群助手 → 添加机器人 → 自定义机器人
2. 安全设置选「加签」,记下 **Webhook 地址** 和 **加签密钥(Secret)**
3. 在 Web 界面「钉钉配置」页填入即可

### DeepSeek(可选)

在 Web 界面填入 API Key 后,系统会对重要漏洞调用 DeepSeek 生成中文摘要。
不填则跳过,系统照常工作。

## 默认监控源

系统内置 28 个监控源,可在 Web 界面增删改。覆盖:

| 类别 | 监控对象 | 数据源 |
|------|----------|--------|
| 操作系统 | Windows Server | NVD 关键词 |
| 操作系统 | Linux 内核 | NVD 关键词 |
| 操作系统 | Microsoft 安全更新 | MSRC RSS |
| NAS | 群晖 DSM | Synology 公告页(HTML) |
| NAS | QNAP | NVD 关键词 |
| 虚拟化 | VMware ESXi / vCenter | NVD 关键词 |
| Web 服务器 | IIS / Nginx / Apache | NVD + nginx 公告页 |
| 数据库 | MySQL / PostgreSQL / SQL Server / Redis / MongoDB / Oracle | NVD 关键词 |
| 语言运行时 | Go / Node.js / Python / OpenJDK | Go OSV + NVD |
| 情报 | 在野利用漏洞 | CISA KEV |
| 情报(国内) | 长亭 / OSCS / 奇安信 / 微步 / Seebug / Struts2 | 官方 API / 公告页 |
| 情报(国内,可选) | 阿里云 AVD / 启明星辰 | 需 Playwright,默认关闭 |

> 国内漏洞源借鉴了 [watchvuln](https://github.com/zema1/watchvuln) 的数据源与过滤策略,对国产软件/办公软件漏洞覆盖更好(国外 NVD 覆盖差)。各源过滤规则:高危/严重 + 标签(预警、POC公开、奇安信CERT验证等)+ 中文标题。

### 启用阿里云 AVD / 启明星辰

这两家有反爬(阿里云盾 JS Challenge / 403),需额外安装 Playwright:

```bash
pip install playwright && playwright install chromium
```

然后在 Web 界面将对应源「启用」即可。

## Ubuntu 部署

完整部署文档见 [DEPLOY.md](DEPLOY.md),支持 Docker 和 systemd 两种方式。

