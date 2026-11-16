# VulnWatch 部署与维护

推荐 Ubuntu 24.04。原生部署需要 Python 3.11+，已验证 Python 3.12；较旧系统可使用 Docker。需要能访问 NVD、CISA 和各公告源。

只能运行一个应用进程、一个 worker 和一个副本，避免内置调度器重复推送。以下为两种独立部署方式，选择一种即可。

## Docker

先安装 Docker Engine 和 Compose，然后获取源码：

```bash
sudo git clone https://github.com/minnana/vulnwatch.git /opt/vulnwatch
cd /opt/vulnwatch
sudo install -m 600 .env.example .env
openssl rand -hex 24
sudoedit .env
```

将生成的随机口令填入 `.env` 的 `VULNWATCH_AUTH_TOKEN`。Compose 默认映射主机的 `8000` 端口；只允许受信任网络访问。反向代理场景可将端口映射改为 `127.0.0.1:8000:8000`。

```bash
sudo docker compose up -d --build
sudo docker compose ps
sudo docker compose logs --tail 100 vulnwatch
```

打开 `http://服务器IP:8000` 并输入口令。数据库持久化在宿主机 `/opt/vulnwatch/data`。Compose 只传递 `docker-compose.yml` 中声明的环境变量；更多参数需要添加到该文件的 `environment` 中。

## systemd（Ubuntu 24.04）

### 安装代码与专用用户

```bash
sudo apt update
sudo apt install -y git python3 python3-venv openssl
sudo git clone https://github.com/minnana/vulnwatch.git /opt/vulnwatch
sudo python3 -m venv /opt/vulnwatch/.venv
sudo /opt/vulnwatch/.venv/bin/pip install -r /opt/vulnwatch/requirements.txt

id vulnwatch >/dev/null 2>&1 || sudo useradd --system --user-group --home-dir /var/lib/vulnwatch --shell /usr/sbin/nologin vulnwatch
sudo install -d -o vulnwatch -g vulnwatch -m 700 /var/lib/vulnwatch
sudo install -m 600 /opt/vulnwatch/.env.example /opt/vulnwatch/.env
openssl rand -hex 24
sudoedit /opt/vulnwatch/.env
```

在 `.env` 设置生成的访问口令。服务默认监听 `127.0.0.1:8000`；需要局域网直连时添加 `VULNWATCH_HOST=服务器内网IP`，使用实际 IP。默认数据目录为 `/var/lib/vulnwatch`，不要使用 Docker 的 `/app/data`。

源码和虚拟环境由 root 持有，服务以 `vulnwatch` 用户运行，只允许写入数据目录。`.env` 由 systemd 读取，无需向服务用户开放文件读取权限。

### 启动并验证

```bash
sudo install -m 644 /opt/vulnwatch/vulnwatch.service /etc/systemd/system/vulnwatch.service
sudo systemctl daemon-reload
sudo systemctl enable --now vulnwatch
sudo systemctl status vulnwatch --no-pager
sudo journalctl -u vulnwatch -n 100 --no-pager
curl -fsS http://127.0.0.1:8000/api/health
```

若设置了特定内网监听 IP，健康检查 URL 也改用该 IP。健康接口正常返回 HTTP 200，数据库异常返回 503。网页外壳公开，设置口令后的数据接口要求认证。对外访问请使用 HTTPS 反向代理。

## 配置与验收

1. 在「配置」填写通知渠道的 Webhook 和加签密钥，保存后发送一条测试消息。
2. 设置推送阈值、产品关键词和每日汇总时间，默认 `09:00 / Asia/Shanghai`。网页修改立即生效，重启后保留。
3. 点击「立即检测并告警」，核对每个源的最近采集结果。每个源首次成功采集只建立历史基线，不推送历史内容。
4. 默认每 10 分钟采集，高危 / 严重 / KEV 即时推送；失败和静默延期保留待推送，每分钟检查重试。严重 / KEV 默认突破静默。概览可手动推送，列表可重发历史记录。
5. 查看最近推送日志；没有符合条件的新内容时不会发送空日报。

内置 28 个源，启用状态可在网页调整。AVD / 启明星辰默认关闭，需额外浏览器依赖。遇到 HTTP 403、限流或页面变化时先停用或修复对应源，不能把失败理解为没有漏洞。成功返回 0 条仍应结合来源页面核对。

KEV 绕过严重级别阈值，但仍受产品关键词和标签筛选约束。DeepSeek 摘要为可选功能，未配置 API Key 不影响采集和通知。

## 备份与恢复

### 在线备份

脚本使用 SQLite Backup API 生成一致快照，并执行 `integrity_check`。不要直接复制运行中的 `.db` 文件来替代在线备份。

```bash
# systemd：输出到 /var/backups/vulnwatch
sudo /opt/vulnwatch/.venv/bin/python /opt/vulnwatch/scripts/backup.py

# Docker：输出到挂载的数据目录，宿主机对应 data/backups
sudo docker compose exec -T vulnwatch python scripts/backup.py --database /app/data/vulnwatch.db --directory /app/data/backups
```

数据库含通知凭证和可选 API Key，备份文件同样敏感。备份目录权限为 `700`，文件为 `600`。脚本不会自动排程或清理旧备份；另行配置备份周期和保留策略。

### systemd 恢复

先选定并核对备份路径，停止服务后保留原数据目录，再恢复备份；不要将旧 WAL 文件与新数据库混用：

```bash
sudo systemctl stop vulnwatch
sudo mv /var/lib/vulnwatch "/var/lib/vulnwatch.before-restore-$(date +%Y%m%dT%H%M%S)"
sudo install -d -o vulnwatch -g vulnwatch -m 700 /var/lib/vulnwatch
# 将下方路径替换为实际的备份文件
sudo install -o vulnwatch -g vulnwatch -m 600 /var/backups/vulnwatch/选定备份.db /var/lib/vulnwatch/vulnwatch.db
sudo systemctl start vulnwatch
sudo systemctl status vulnwatch --no-pager
```

Docker 恢复同样先 `docker compose down`，保留原 `data/` 目录，将选定备份安装为新目录的 `data/vulnwatch.db`，再启动。确保容器运行用户能读写新目录；不要删除原目录直到恢复验证完成。

## 从 0.3.0 升级到 0.3.1

沿用下面的在线备份、更新源码及重启流程，无需迁移数据目录。启动只补齐缺失配置，保留现有即时阈值。想减少打扰，在配置页最上方点击「安静模式（推荐）」：严重 / KEV 即时提醒，高危每日汇总。新的历史公告过滤默认 7 天，按首次入库时的公告年龄判断，KEV 例外。

概览可分别暂停 / 恢复定时检测与自动推送；前者不取消正在执行的一轮，后者保留待推送记录。合并、去重、历史过滤的具体边界见 README。

## 从 0.2.1 升级到 0.3.0

先在线备份数据库，保存当前提交、.env 与 service 文件；停止服务后更新源码和依赖，再启动。沿用原数据目录、专用用户和访问口令，无需重新迁移或更换服务文件。

启动自动添加 AI 调用记录表与缺失配置，**保留现有历史基线和回执**。默认开启每 10 分钟检测及高危 / 严重 / KEV 即时推送，已有符合条件的待推送记录可能在下一分钟发送。09:00 仅汇总剩余内容，无 Key 时 AI 默认关闭。完整逻辑见 [README](README.md)。

验收健康接口版本 0.3.0、原漏洞数量、通知配置、下次检测时间和弹窗保存。用通道测试消息验证签名，不向生产数据库灌入虚假漏洞。回退需同时恢复升级前源码和数据库备份。

## 更早版本升级的目录迁移（0.2.1 引入）

### systemd 数据迁移

旧版可能使用 `/opt/vulnwatch/venv` 和 `/opt/vulnwatch/data`，新服务使用 `.venv` 和 `/var/lib/vulnwatch`。先停止旧服务并备份旧数据库，再替换服务配置；不要直接启动指向空目录的新服务。

1. `sudo systemctl stop vulnwatch`，确认旧服务已停止。
2. 记录当前提交：`sudo git -C /opt/vulnwatch rev-parse HEAD`，另行保存旧 `.env` 和服务文件。
3. 保留一份旧数据目录备份；服务停止后再复制整个目录，包含存在的 WAL/SHM 文件。
4. `sudo git -C /opt/vulnwatch pull --ff-only`；如有本地修改或分叉，先核对合并，不要强制覆盖。
5. 按上方安装步骤创建专用用户、数据目录和 `.venv`，安装当前依赖。不要重新覆盖已有 `.env`。
6. 用备份脚本导出旧数据库到新目录，再设置所有权：

```bash
sudo /opt/vulnwatch/.venv/bin/python /opt/vulnwatch/scripts/backup.py --database /opt/vulnwatch/data/vulnwatch.db --directory /var/backups/vulnwatch
# 使用脚本实际输出的文件路径
sudo install -o vulnwatch -g vulnwatch -m 600 /var/backups/vulnwatch/实际备份.db /var/lib/vulnwatch/vulnwatch.db
```

7. 修改已有 `.env`：移除旧 `VULNWATCH_DB` / `VULNWATCH_DATA_DIR`，或指向 `/var/lib/vulnwatch` 下的数据库；核对访问口令和监听 IP。
8. 安装新服务文件，执行 `daemon-reload`、启动服务，核对原配置、漏洞数量和健康接口。

首次启动自动新建回执与源状态表，保留原配置和漏洞。升级后每个源首次成功采集会重新建立基线，这轮历史内容不会推送。

已经使用本版目录结构时，先在线备份，再停止服务、`git pull --ff-only`、安装 `requirements.txt`、同步服务文件并重启即可。回退时配合升级前的数据库备份及服务配置。

### Docker 更新

先执行在线备份，记录旧提交，再运行 `docker compose down`、`git pull --ff-only`、`docker compose up -d --build`。保留原 `data/` 挂载目录。首次采集基线规则与 systemd 一致。

## 离线验证

```bash
python -m pip install -r requirements-dev.txt
python scripts/smoke_test.py
python tests/test_reliability.py
python -m pip check
```

测试使用独立临时数据库，不向实际机器人发送消息。`requirements.lock.txt` 是 Ubuntu / Python 3.12 验证环境的完整依赖快照（含测试依赖和 Linux 的 uvloop），其他平台使用 `requirements.txt`。
