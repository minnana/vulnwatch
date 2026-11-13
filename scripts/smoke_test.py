#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""VulnWatch 冒烟测试（离线运行，不访问任何外部网络）。

覆盖范围：
  1. 所有模块可导入（语法/导入关系正确）
  2. 13 种采集器都能按 source_type 正确实例化
  3. FastAPI 接口：健康检查、监控源增删改查、漏洞列表、统计、配置读写、
     采集状态、首页与静态资源
  4. 数据库批量写入：幂等、ai_summary 不被覆盖、查询/统计
  5. 推送日报：按字节上限自动分片、KEV 分组
  6. 调度辅助函数：HH:MM 解析、KEV 优先去重、静默时段
  7. 参数校验：非法 URL 协议被拦截

用法（在项目根目录执行）：
    python scripts/smoke_test.py

依赖：requirements.txt + requirements-dev.txt（含 httpx，TestClient 需要）。
退出码：0 表示全部通过，1 表示存在失败项。
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# 必须在导入 app.* 之前设置：使用临时数据目录，避免污染真实 data/ 与数据库
_TMP_DIR = tempfile.mkdtemp(prefix="vulnwatch-smoke-")
os.environ["VULNWATCH_DATA_DIR"] = _TMP_DIR
os.environ["VULNWATCH_DB"] = os.path.join(_TMP_DIR, "smoke.db")
os.environ["VULNWATCH_AUTH_TOKEN"] = ""
# 关闭 NVD 批量模式，保证测试不依赖外部网络行为
os.environ["VULNWATCH_NVD_BULK"] = "0"

_PASSED: list = []
_FAILED: list = []
# 注册表：装饰器只登记，main() 里统一执行一次
_TESTS: list = []


def check(name):
    """装饰器：登记一个测试函数（不在此处执行）。"""

    def wrapper(fn):
        _TESTS.append((name, fn))
        return fn

    return wrapper


def _fresh_client():
    """创建一个 TestClient（会触发 lifespan：建表、初始化默认数据、启动调度器）。"""
    try:
        from fastapi.testclient import TestClient
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "缺少 httpx（FastAPI TestClient 依赖）。"
            "请先执行: pip install -r requirements-dev.txt"
        ) from exc
    from app.main import app

    return TestClient(app)


# --------------------------------------------------------------------------
# 1. 模块导入
# --------------------------------------------------------------------------
@check("模块导入与版本号")
def test_imports():
    import app.config  # noqa: F401
    import app.database  # noqa: F401
    import app.models  # noqa: F401
    import app.schemas  # noqa: F401
    import app.crud  # noqa: F401
    import app.notifier  # noqa: F401
    import app.scheduler  # noqa: F401
    import app.summarize  # noqa: F401
    import app.collectors  # noqa: F401
    import app.main as main

    assert main.APP_VERSION, "APP_VERSION 不能为空"


# --------------------------------------------------------------------------
# 2. 采集器注册表
# --------------------------------------------------------------------------
@check("13 种采集器均可实例化")
def test_collectors():
    from types import SimpleNamespace

    from app.collectors import get_collector
    from app.schemas import SOURCE_TYPES

    types_ = list(SOURCE_TYPES.__args__)
    assert len(types_) == 13, "SOURCE_TYPES 数量应为 13，实际 %d" % len(types_)
    for source_type in types_:
        source = SimpleNamespace(
            id=1,
            name="smoke",
            category="Test",
            source_type=source_type,
            url="https://example.com/",
            cpe=None,
            keyword=None,
            enabled=True,
            created_at=None,
        )
        collector = get_collector(source)
        assert collector is not None, "采集器为空: %s" % source_type
        assert getattr(collector, "source", None) is source


# --------------------------------------------------------------------------
# 3. HTTP 接口（单个 TestClient 上下文，避免重复启动调度器）
# --------------------------------------------------------------------------
@check("FastAPI 接口与默认数据")
def test_api():
    with _fresh_client() as client:
        # 健康检查（无需口令）
        resp = client.get("/api/health")
        assert resp.status_code == 200, resp.text
        health = resp.json()
        assert health.get("status") == "ok", "健康检查状态异常: %s" % health
        assert health.get("version"), "健康检查缺少 version"
        assert health.get("database") == "ok", "数据库检查异常: %s" % health

        # 默认监控源：至少 28 个（后续版本可能追加新源）
        resp = client.get("/api/sources")
        assert resp.status_code == 200, resp.text
        sources = resp.json()
        assert len(sources) >= 28, "默认监控源应不少于 28 个，实际 %d" % len(sources)
        names = {s.get("name") for s in sources}
        assert "Windows Server" in names, "默认监控源缺少 Windows Server"

        # 统计接口（一次请求返回全部计数）
        resp = client.get("/api/stats?days=7")
        assert resp.status_code == 200, resp.text
        stats = resp.json()
        for key in ("total", "critical", "high", "kev", "ai_summary"):
            assert key in stats, "统计字段缺失: %s" % key

        # 漏洞列表分页结构
        resp = client.get("/api/vulnerabilities")
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert "total" in data and "items" in data, "漏洞列表应返回 total/items"
        assert isinstance(data["items"], list)

        # 配置读取 + 批量写入
        resp = client.get("/api/settings")
        assert resp.status_code == 200, resp.text
        settings = resp.json()
        assert settings.get("notify_channel") == "dingtalk"

        resp = client.put(
            "/api/settings",
            json={
                "values": {
                    "notify_channel": "dingtalk",
                    "alert_threshold": "CRITICAL",
                    "daily_time": "08:30",
                }
            },
        )
        assert resp.status_code == 200, resp.text
        settings = client.get("/api/settings").json()
        assert settings.get("alert_threshold") == "CRITICAL", "批量保存配置未生效"
        assert settings.get("daily_time") == "08:30", "daily_time 未保存"

        # 留空 daily_time 不应导致整批保存失败
        resp = client.put("/api/settings", json={"values": {"daily_time": ""}})
        assert resp.status_code == 200, "留空 daily_time 不应该让整批配置 400: %s" % resp.text

        # 非法通知通道应被拒绝
        resp = client.put("/api/settings", json={"values": {"notify_channel": "nope"}})
        assert resp.status_code == 400, "非法通知通道应返回 400，实际 %d" % resp.status_code

        # 监控源 CRUD
        payload = {
            "name": "smoke-api",
            "category": "Test",
            "source_type": "html",
            "url": "https://example.com/advisories",
            "enabled": False,
        }
        resp = client.post("/api/sources", json=payload)
        assert resp.status_code == 200, resp.text
        source_id = resp.json()["id"]

        resp = client.get("/api/sources/%d" % source_id)
        assert resp.status_code == 200 and resp.json()["name"] == "smoke-api"

        resp = client.put("/api/sources/%d" % source_id, json={"name": "smoke-api-2"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["name"] == "smoke-api-2", "更新监控源未生效"

        resp = client.delete("/api/sources/%d" % source_id)
        assert resp.status_code == 200
        resp = client.get("/api/sources/%d" % source_id)
        assert resp.status_code == 404, "删除后的监控源应返回 404"

        # 非法 URL 协议应返回 422
        bad = dict(payload, url="ftp://example.com/advisories")
        resp = client.post("/api/sources", json=bad)
        assert resp.status_code == 422, "非法 URL 协议应返回 422，实际 %d" % resp.status_code

        # 采集状态
        resp = client.get("/api/collect/status")
        assert resp.status_code == 200, resp.text
        assert "running" in resp.json()

        # 首页与静态资源（不要求登录口令）
        resp = client.get("/")
        assert resp.status_code == 200, "首页应返回 200，实际 %d" % resp.status_code
        assert "VulnWatch" in resp.text, "首页内容异常"
        resp = client.get("/static/index.html")
        assert resp.status_code == 200, "静态页面应返回 200，实际 %d" % resp.status_code


# --------------------------------------------------------------------------
# 4. 数据库批量写入
# --------------------------------------------------------------------------
@check("批量写入：幂等 + 保留 ai_summary")
def test_crud_batch():
    from app import config, crud, models
    from app.database import SessionLocal
    from app.schemas import MonitorSourceCreate

    db = SessionLocal()
    try:
        source = crud.create_source(
            db,
            MonitorSourceCreate(
                name="smoke-source",
                category="Test",
                source_type="nvd_cpe",
                url="https://example.com/",
                enabled=False,
            ),
        )
        item = {
            "cve_id": "cve-2099-0001",
            "title": "冒烟测试漏洞",
            "severity": "HIGH",
            "cvss_score": 8.1,
            "published_at": config.utcnow(),
            "url": "https://example.com/cve",
        }

        new_count, new_items = crud.upsert_many(db, source.id, [dict(item)])
        assert new_count == 1, "首次写入应为 1 条，实际 %d" % new_count
        assert new_items and new_items[0].get("id"), "新漏洞应包含 id"
        vuln_id = new_items[0]["id"]

        # 重复采集：不应重复插入
        new_count2, _ = crud.upsert_many(db, source.id, [dict(item)])
        assert new_count2 == 0, "重复写入应为 0 条，实际 %d" % new_count2

        # AI 摘要不应在下次采集时被 NULL 覆盖（回归测试）
        crud.update_ai_summaries(db, {vuln_id: "AI 摘要"})
        updated = dict(item)
        updated["title"] = "冒烟测试漏洞（已更新）"
        updated["ai_summary"] = None
        crud.upsert_many(db, source.id, [updated])

        db.expire_all()
        row = db.get(models.Vulnerability, vuln_id)
        assert row is not None, "漏洞记录丢失"
        assert row.title.endswith("（已更新）"), "字段更新未生效"
        assert row.ai_summary == "AI 摘要", "重复采集把 ai_summary 覆盖为 NULL"

        # 列表查询与统计
        items, total = crud.list_vulnerabilities(db, None, None, None, 3650, 50, 0)
        assert total >= 1, "漏洞总数应 >= 1"
        assert any(getattr(it, "source_name", None) == "smoke-source" for it in items), (
            "列表应带出 source_name"
        )
        stats = crud.stats(db, 3650)
        assert stats["total"] >= 1, "统计总数应 >= 1"

        crud.delete_source(db, source.id)
    finally:
        db.close()


# --------------------------------------------------------------------------
# 5. 日报分片
# --------------------------------------------------------------------------
@check("推送日报：自动分片 + KEV 分组")
def test_notifier():
    from app import config, notifier

    vulns = []
    for i in range(120):
        vulns.append(
            {
                "cve_id": "CVE-2099-%04d" % i,
                "title": "很长的漏洞标题" * 6,
                "severity": "CRITICAL" if i % 3 == 0 else "HIGH",
                "cvss_score": 9.8,
                "is_kev": i == 0,
                "tags": "在野利用,RCE",
                "affected": "示例产品 1.0 到 2.0 版本，默认配置下可远程触发",
                "url": "https://example.com/vuln",
                "ai_summary": "示例 AI 摘要",
            }
        )

    messages = notifier.build_report_messages(vulns, "HIGH", 120)
    assert messages, "分片结果不能为空"
    assert len(messages) >= 2, "120 条漏洞应被拆分为多条消息"
    for message in messages:
        size = len(message.encode("utf-8"))
        # 分片预算为 PUSH_MAX_BYTES - 600,再加标题/页脚,理应不超过硬上限
        assert size <= config.PUSH_MAX_BYTES, "分片超出推送字节上限: %d" % size
        assert "每日漏洞情报汇总" in message
    assert any("在野利用" in message for message in messages), "缺少 KEV 分组"
    assert notifier.build_report(vulns, "HIGH", 5), "单条合并报告不能为空"


# --------------------------------------------------------------------------
# 6. 调度辅助函数
# --------------------------------------------------------------------------
@check("调度辅助函数：时间解析 / KEV 优先去重 / 静默时段")
def test_scheduler_helpers():
    from app import crud, scheduler
    from app.database import SessionLocal

    assert scheduler.parse_hhmm("09:30") == (9, 30)
    assert scheduler.parse_hhmm("7：05") == (7, 5), "应支持全角冒号"
    assert scheduler.parse_hhmm("00:00") == (0, 0)
    assert scheduler.parse_hhmm("24:00") is None, "24:00 应判定为非法"
    assert scheduler.parse_hhmm("abc") is None

    deduped = scheduler._dedup_by_cve(
        [
            {
                "cve_id": "CVE-2099-9",
                "is_kev": False,
                "severity": "HIGH",
                "cvss_score": 9.0,
                "unique_key": "a",
            },
            {
                "cve_id": "CVE-2099-9",
                "is_kev": True,
                "severity": "MEDIUM",
                "cvss_score": 5.0,
                "unique_key": "b",
            },
        ]
    )
    assert len(deduped) == 1, "同一 CVE 应去重为 1 条"
    assert deduped[0]["is_kev"] is True, "去重时应优先保留 KEV 记录"

    db = SessionLocal()
    try:
        crud.set_settings(db, {"silent_hours_enabled": "false"})
        assert scheduler._is_silent_time(db) is False, "未开启静默时段时应为 False"
        crud.set_settings(
            db,
            {
                "silent_hours_enabled": "true",
                # 00:00–00:00 走跨天分支（now >= start or now < end），恒为真，
                # 避免用 23:59 结尾时恰好在 23:59:00–23:59:59 之间偶发失败。
                "silent_hours_start": "00:00",
                "silent_hours_end": "00:00",
            },
        )
        assert scheduler._is_silent_time(db) is True, "全天静默时应为 True"
    finally:
        crud.set_settings(db, {"silent_hours_enabled": "false"})
        db.close()


# --------------------------------------------------------------------------
# 7. 请求模型校验
# --------------------------------------------------------------------------
@check("请求模型校验：非法 URL 协议被拦截")
def test_validation():
    from pydantic import ValidationError

    from app.schemas import MonitorSourceCreate

    try:
        MonitorSourceCreate(
            name="x", category="Test", source_type="html", url="ftp://example.com/"
        )
    except ValidationError:
        pass
    else:
        raise AssertionError("ftp:// 协议应被拒绝")


def main() -> int:
    print("=" * 60)
    print("VulnWatch 冒烟测试（临时数据目录: %s）" % _TMP_DIR)
    print("=" * 60)

    # 顺序按装饰顺序执行：API 测试负责建表与初始化默认数据
    for name, fn in _TESTS:
        try:
            fn()
        except Exception:  # noqa: BLE001 - 测试脚本需要收集所有失败
            _FAILED.append((name, traceback.format_exc()))
            print("[失败] %s" % name)
            for line in traceback.format_exc().strip().splitlines()[-3:]:
                print("       " + line.strip())
        else:
            _PASSED.append(name)
            print("[通过] %s" % name)

    # 归还数据库文件句柄后再删临时目录
    try:
        from app.database import engine

        engine.dispose()
    except Exception:  # noqa: BLE001
        pass
    shutil.rmtree(_TMP_DIR, ignore_errors=True)

    print("-" * 60)
    print("结果: 通过 %d 项, 失败 %d 项" % (len(_PASSED), len(_FAILED)))
    if _FAILED:
        print("失败详情:")
        for name, detail in _FAILED:
            print("\n### %s" % name)
            print(detail)
        return 1
    print("全部冒烟测试通过。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
