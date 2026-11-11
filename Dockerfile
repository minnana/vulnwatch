FROM python:3.12-slim

WORKDIR /app

# 先复制依赖文件,利用缓存
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY app ./app
COPY static ./static
COPY run.py .

# 数据目录
RUN mkdir -p /app/data
VOLUME ["/app/data"]

EXPOSE 8000

# 时区设置为上海(影响定时任务与日志)
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

CMD ["python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
