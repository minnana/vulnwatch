FROM python:3.12-slim

# PYTHONUNBUFFERED:日志实时输出(Python 3.7 起无需 -u)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    TZ=Asia/Shanghai \
    VULNWATCH_TIMEZONE=Asia/Shanghai \
    VULNWATCH_DATA_DIR=/app/data

WORKDIR /app

# 非交互安装,避免 CI/伪终端下 debconf 卡住
ARG DEBIAN_FRONTEND=noninteractive

# slim 镜像可能不带 /usr/share/zoneinfo,显式安装 tzdata 并设置容器时区
RUN apt-get update \
    && apt-get install -y --no-install-recommends tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && ln -snf /usr/share/zoneinfo/$TZ /etc/localtime \
    && echo $TZ > /etc/timezone

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static
COPY run.py .

RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 8000

# 健康检查直接复用 /api/health(该路径不需要口令)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3).status == 200 else 1)"

# 必须单进程(单 worker):APScheduler 与 SQLite 均在进程内。
# 默认以 root 运行,便于挂载宿主机 ./data 目录;如需非 root,请自行调整目录属主后加 USER。
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--proxy-headers"]
