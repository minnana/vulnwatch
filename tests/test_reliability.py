"""Offline regression tests for delivery persistence and deployment safeguards."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
TMP = tempfile.TemporaryDirectory(prefix="vulnwatch-regression-")
os.environ["VULNWATCH_DATA_DIR"] = TMP.name
os.environ["VULNWATCH_DB"] = str(Path(TMP.name) / "test.db")
os.environ["VULNWATCH_AUTH_TOKEN"] = "test-only-token"

from app import crud, models, notifier, scheduler, config
from app.database import Base, SessionLocal, engine
from app.schemas import MonitorSourceCreate


def item(cve="CVE-2099-1000", kev=False):
    return dict(cve_id=cve, title="Test vulnerability", severity="HIGH",
                is_kev=kev, url="https://example.com/advisory")


class ReliabilityTests(unittest.TestCase):
    def setUp(self):
        Base.metadata.drop_all(engine)
        Base.metadata.create_all(engine)
        self.db = SessionLocal()
        self.source = crud.create_source(self.db, MonitorSourceCreate(
            name="test", category="Test", source_type="html", url="https://example.com"))
        crud.set_settings(self.db, {"dingtalk_webhook": "test-placeholder", "alert_threshold": "HIGH"})

    def tearDown(self):
        self.db.close()

    def collect(self, rows, source=None):
        with patch.object(scheduler, "get_collector", return_value=SimpleNamespace(collect=lambda: rows)):
            return scheduler.collect_source(self.db, source or self.source)

    def run_daily(self, outcome=True):
        with patch.object(scheduler, "collect_all", return_value=[]), \
             patch.object(scheduler, "send", return_value=outcome) as send:
            scheduler.run_daily_job()
            return send

    def test_first_collection_is_baseline(self):
        self.assertTrue(self.collect([item()])["baseline"])
        self.assertEqual(crud.pending_notifications(self.db), [])
        self.run_daily().assert_not_called()

    def test_manual_collection_delivered_and_not_repeated(self):
        self.collect([item()])
        self.collect([item(), item("CVE-2099-1001")])
        self.assertEqual(len(crud.pending_notifications(self.db)), 1)
        self.run_daily().assert_called_once()
        self.run_daily().assert_not_called()

    def test_failed_delivery_survives_new_session(self):
        self.collect([])
        self.collect([item()])
        self.run_daily(False).assert_called_once()
        with SessionLocal() as db:
            self.assertEqual(len(crud.pending_notifications(db)), 1)
        self.run_daily(True).assert_called_once()
        self.run_daily().assert_not_called()

    def test_silent_window_defers_without_losing_alerts(self):
        self.collect([])
        self.collect([item()])
        with patch.object(scheduler, "_is_silent_time", return_value=True):
            self.run_daily().assert_not_called()
        self.run_daily().assert_called_once()

    def test_failed_source_does_not_initialize_baseline(self):
        with patch.object(scheduler, "get_collector", side_effect=RuntimeError("HTTP 403")):
            result = scheduler.collect_source(self.db, self.source)
        self.assertIn("403", result["error"])
        self.assertIsNone(self.db.get(models.SourceCollectionState, self.source.id).first_success_at)
        self.assertTrue(self.collect([item()])["baseline"])
        self.run_daily().assert_not_called()

    def test_new_source_baseline_and_cross_day_cve_dedup(self):
        self.collect([])
        self.collect([item()])
        self.run_daily().assert_called_once()
        other = crud.create_source(self.db, MonitorSourceCreate(
            name="other", category="Test", source_type="html", url="https://example.com"))
        self.assertTrue(self.collect([item("CVE-2099-2000")], other)["baseline"])
        self.collect([item(), item("CVE-2099-2000")], other)
        self.run_daily().assert_not_called()

    def test_kev_escalation_delivered_once(self):
        self.collect([item()])
        self.collect([item(kev=True)])
        self.run_daily().assert_called_once()
        self.run_daily().assert_not_called()

    def test_synology_advisory_is_idempotent(self):
        from app.collectors.html import HtmlCollector
        rows = HtmlCollector(self.source)._parse('<a href="/advisory/1">Synology-SA-26:19 HIGH</a>')
        self.assertEqual(rows[0]["unique_key"], "Synology-SA-26:19")
        self.assertEqual(self.collect(rows)["new_count"], 1)
        self.assertEqual(self.collect(rows)["new_count"], 0)

    def test_severity_words_do_not_match_substrings(self):
        from app.collectors.severity import guess_severity
        self.assertEqual(guess_severity("Uninitialized resource"), "UNKNOWN")
        self.assertEqual(guess_severity("Integer overflow"), "UNKNOWN")
        self.assertEqual(guess_severity("Remote Code Execution"), "CRITICAL")
        self.assertEqual(guess_severity("Severity: low"), "LOW")

    def test_html_rows_do_not_mix_severity_and_base_url(self):
        from app.collectors.html import HtmlCollector
        content = '''<base href="https://www.synology.com/">
        <tr><td><a href="security/advisory/a">Synology-SA-26:19 DSM</a></td><td>Medium</td></tr>
        <tr><td><a href="security/advisory/b">Synology-SA-26:18 DSM</a></td><td>Critical</td></tr>'''
        rows = HtmlCollector(self.source)._parse(content)
        self.assertEqual([r["severity"] for r in rows], ["MEDIUM", "CRITICAL"])
        self.assertEqual(rows[0]["url"], "https://www.synology.com/security/advisory/a")
        content = '<li><p>Buffer overflow<br>Severity: medium<br><a href="https://example.com/a">CVE-2099-1111</a></p></li>'
        self.assertEqual(HtmlCollector(self.source)._parse(content)[0]["severity"], "MEDIUM")

    def test_all_records_batched_and_message_size_bounded(self):
        rows = [item(f"CVE-2099-{i:04}") for i in range(123)]
        rows[0]["tags"] = "中文" * 5000
        batches = notifier.build_report_batches(rows)
        self.assertEqual(sum(len(records) for _, records in batches), 123)
        for text, records in batches:
            self.assertLessEqual(len(text.encode()), config.PUSH_MAX_BYTES)
            self.assertTrue(records)

    def test_partial_delivery_only_retries_unsent_chunks(self):
        self.collect([])
        self.collect([item(f"CVE-2099-{i:04}") for i in range(60)])
        with patch.object(scheduler, "collect_all", return_value=[]), \
             patch.object(scheduler, "send", side_effect=[True, False]) as send, \
             patch("time.sleep"):
            scheduler.run_daily_job()
        self.assertEqual(send.call_count, 2)
        pending = crud.pending_notifications(self.db)
        self.assertGreater(len(pending), 0)
        self.assertLess(len(pending), 60)

    def test_http_failure_is_not_empty_success(self):
        import requests
        from app.collectors.base import BaseCollector
        response = requests.Response()
        response.status_code = 403
        response.url = "https://example.com"
        with patch("app.collectors.base.get_session") as session, \
             patch("app.collectors.base.RETRY_TIMES", 0):
            session.return_value.request.return_value = response
            with self.assertRaises(requests.HTTPError):
                BaseCollector(self.source)._http_get(response.url, _skip_throttle=True)

    def test_auth_collection_lock_and_health_status(self):
        from fastapi.testclient import TestClient
        from app.main import app
        with TestClient(app) as client:
            self.assertEqual(client.get("/api/settings").status_code, 401)
            self.assertEqual(client.get("/api/health").status_code, 200)
            headers = {"Authorization": "Bearer test-only-token"}
            self.assertEqual(client.get("/api/settings", headers=headers).status_code, 200)
            self.assertTrue(scheduler.begin_collection())
            try:
                self.assertEqual(client.post(f"/api/collect/{self.source.id}", headers=headers).status_code, 409)
            finally:
                scheduler.end_collection()
            with patch("app.main.SessionLocal", side_effect=RuntimeError("database unavailable")):
                self.assertEqual(client.get("/api/health").status_code, 503)


if __name__ == "__main__":
    try:
        unittest.main(verbosity=2)
    finally:
        engine.dispose()
        TMP.cleanup()
