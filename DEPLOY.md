# VulnWatch 部署指南(Ubuntu 服务器)

本文档面向你提供的 Ubuntu 服务器,提供两种部署方式:**Docker**(推荐)和 **systemd + 虚拟环境**。

---

## 一、环境要求

- Ubuntu 20.04 / 22.04 / 24.04
- Python 3.10+(仅 systemd 方式需要)
- 可访问外网(采集器需访问 NVD、CISA、各厂商官网)
- 防火墙放行 8000 端口(或由 Nginx 反向代理)

---

## 二、方式一:Docker 部署(推荐)

### 1. 上传代码到服务器

```bash
# 把整个项目目录上传到服务器,例如 /opt/vulnwatch
scp -r 项目目录 ubuntu@服务器IP:/opt/vulnwatch
```

### 2. 安装 Docker(如已安装可跳过)

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
# 重新登录使权限生效
```

### 3. 构建并启动

```bash
cd /opt/vulnwatch
docker compose up -d --build
```

### 4. 查看日志

```bash
docker compose logs -f vulnwatch
```

### 5. 访问

浏览器打开 `http://服务器IP:8000`

---

## 三、方式二:systemd + 虚拟环境

### 1. 上传代码

```bash
sudo mkdir -p /opt/vulnwatch
sudo chown $USER:$USER /opt/vulnwatch
# 上传代码到 /opt/vulnwatch
```

### 2. 安装依赖

```bash
cd /opt/vulnwatch
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. 注册 systemd 服务

```bash
sudo cp vulnwatch.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable vulnwatch
sudo systemctl start vulnwatch
```

### 4. 查看状态

```bash
sudo systemctl status vulnwatch
sudo journalctl -u vulnwatch -f
```

---

## 四、配置(两种方式通用)

### 1. 钉钉机器人配置

1. 打开钉钉群 → 右上角「群设置」→「智能群助手」→「添加机器人」→「自定义机器人」
2. 安全设置选择 **「加签」**,记下生成的 **Webhook 地址** 和 **加签密钥(Secret)**
3. 登录 VulnWatch Web 界面 → 「配置」→ 填入 Webhook 和 Secret → 保存 → 点「发送测试消息」验证

> 钉钉机器人「加签」方式无需配置关键词,是最稳妥的安全设置。

### 2. 告警阈值

在「配置」页设置推送阈值,默认「高危及以上」。
- 仅严重 / 高危及以上 / 中危及以上 / 全部
- **在野利用漏洞(CISA KEV)无论阈值如何,始终推送**

### 3. DeepSeek(可选)

在「配置」页填入 DeepSeek API Key。填入后系统可对重要漏洞生成中文摘要。
不填则跳过,主链路(采集 + 告警 + 推送)完全不受影响。

### 4. 每日汇总时间

通过环境变量设置(默认每天 09:00):

```bash
# Docker: 修改 docker-compose.yml 中的环境变量
VULNWATCH_DAILY_HOUR=9
VULNWATCH_DAILY_MINUTE=0

# systemd: 修改 vulnwatch.service 中的 Environment
```

### 5. 访问认证(强烈建议上生产前开启)

系统默认**匿名可访问**,适合内网 demo。**部署到公网或多人环境前,务必设置访问口令**:

```bash
# Docker: 在 docker-compose.yml 的 environment 中添加
VULNWATCH_AUTH_TOKEN=你的随机口令

# systemd: 在 vulnwatch.service 的 Environment 中添加
Environment=VULNWATCH_AUTH_TOKEN=你的随机口令
```

设置后,访问 Web 界面会被提示输入口令;也可通过 `?token=口令` 或 `Authorization: Bearer 口令` 访问 API。

> 口令请用足够强的随机串,例如 `openssl rand -hex 16`。

---

## 五、Nginx 反向代理(可选,便于加 HTTPS 或改端口)

```nginx
server {
    listen 80;
    server_name vulnwatch.example.com;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

---

## 六、监控源管理

系统内置 20 个默认监控源,可在 Web 界面「监控源」页增删改:

| 类型 | 说明 | 适用 |
|------|------|------|
| NVD 关键词/CPE | 按产品名关键词搜索 NVD | 通用产品(数据库、运行时等) |
| RSS / Atom | 解析 RSS feed | MSRC 等有 RSS 的厂商 |
| HTML 公告页 | 正则解析公告页 | Synology、nginx 等静态公告页 |
| Go 官方漏洞库 | OSV 格式 | Go 标准库/工具链 |
| CISA KEV | 在野利用目录 | 必配 |

**新增监控源**只需填:名称 + 类别 + 类型 + URL(+ 关键词或 CPE)。

---

## 七、数据存储

- 数据库:SQLite,位于 `data/vulnwatch.db`
- 备份:直接复制 `data/` 目录即可

```bash
# 备份
tar -czf vulnwatch-backup-$(date +%F).tar.gz data/

# 恢复
tar -xzf vulnwatch-backup-2026-11-10.tar.gz
```

---

## 八、常见问题

**Q: 首次部署时推送了大量历史漏洞?**
A: 首次采集会建立历史基线,部分公告页(如 nginx)会收录全部历史 CVE。这是正常现象,后续每日只会推送**新增**的漏洞。

**Q: 某些源采集到 0 条?**
A: 可能该产品近期无新漏洞,或关键词不准确。可在「监控源」页调整关键词后点「采集」单源重试。

**Q: NVD 采集有频率限制?**
A: 系统内置了按域名的请求间隔限速(默认 1 秒,NVD 单独 6 秒),避免触发限流。可在环境变量 `VULNWATCH_REQUEST_INTERVAL` 调整。

**Q: 如何只监控我关心的产品?**
A: 在「监控源」页停用不需要的源,或新增自定义源。
