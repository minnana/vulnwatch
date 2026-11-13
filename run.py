"""本地运行入口:python run.py

生产环境也可以用:
    uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 1
注意:内置 APScheduler 与 SQLite 都在进程内,只能单进程/单 worker 运行。
"""
import os

import uvicorn

if __name__ == "__main__":
    host = os.getenv("VULNWATCH_HOST", "0.0.0.0")
    port = int(os.getenv("VULNWATCH_PORT", "8000"))
    uvicorn.run("app.main:app", host=host, port=port, reload=False, workers=1)
