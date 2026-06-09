import json
import os
import tempfile
import unittest


os.environ["IDS_AUTH_DISABLED"] = "1"
os.environ["IDS_DB_PATH"] = tempfile.NamedTemporaryFile(prefix="netwatch-test-", suffix=".sqlite3", delete=True).name

import app  # noqa: E402


class IDSCoreTests(unittest.TestCase):
    def test_demo_cases_include_major_labels(self):
        cases = app.STATE.demo_cases()
        labels = {case["prediction"]["label"] for case in cases}
        self.assertIn("normal", labels)
        self.assertIn("dos", labels)
        self.assertIn("probe", labels)
        self.assertIn("botnet", labels)

    def test_credential_abuse_specialist_routes_r2l(self):
        result = app.STATE.run_demo_case("r2l")["flow"]["prediction"]
        self.assertEqual(result["label"], "r2l")
        self.assertEqual(result["recommended_action"]["type"], "alert")
        self.assertEqual(result["ensemble"]["decision"], "credential-specialist")

    def test_csv_batch_prediction(self):
        csv_text = """source_ip,destination_ip,source_bytes,destination_bytes,packet_count,duration,failed_login_count,connection_rate,same_host_rate,error_rate,protocol,service,flag
10.10.1.12,172.217.166.4,6448,1152,48,112.74069,0,0.425755776,0,0,tcp,http,SF
185.44.77.10,10.10.1.40,196,128,9,0.081379,0,110.5936421,0,0.2222222222,tcp,http,S0
"""
        payload = app.STATE.analyze_csv(csv_text, limit=10)
        self.assertEqual(payload["rows"], 2)
        self.assertEqual(payload["summary"]["attack"], 1)
        self.assertEqual(payload["summary"]["breakdown"]["Botnet / Suspicious Traffic"], 1)

    def test_settings_update_is_bounded(self):
        original = dict(app.STATE.settings)
        try:
            updated = app.STATE.apply_settings(
                {
                    "capture_seconds": 99,
                    "csv_row_limit": 5000,
                    "high_risk_confidence": 0,
                    "r2l_specialist_enabled": False,
                },
                persist=False,
            )
            self.assertEqual(updated["capture_seconds"], 10)
            self.assertEqual(updated["csv_row_limit"], 1000)
            self.assertEqual(updated["high_risk_confidence"], 1)
            self.assertFalse(updated["r2l_specialist_enabled"])
        finally:
            app.STATE.apply_settings(original, persist=False)

    def test_exports_are_generated(self):
        report = app.STATE.export_report()
        self.assertIn("dashboard", report)
        self.assertIn("model", report)
        predictions_csv = app.STATE.predictions_csv()
        self.assertIn("source_ip,destination_ip,label,confidence", predictions_csv)
        defense_csv = app.STATE.defense_csv()
        self.assertIn("timestamp,source_ip,label,action,severity,type", defense_csv)

    def test_auth_manager(self):
        original = os.environ.get("IDS_AUTH_DISABLED")
        os.environ["IDS_AUTH_DISABLED"] = "0"
        try:
            manager = app.AuthManager()
            token = manager.login(manager.passcode)
            self.assertIsNotNone(token)
            self.assertTrue(manager.authenticated({"Cookie": f"ids_session={token}"}))
            self.assertIsNone(manager.login("wrong-passcode"))
        finally:
            if original is None:
                os.environ.pop("IDS_AUTH_DISABLED", None)
            else:
                os.environ["IDS_AUTH_DISABLED"] = original


if __name__ == "__main__":
    unittest.main()
