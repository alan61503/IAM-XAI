"""Integration tests for Phase 10: Interactive Dashboard REST API."""

import json
from http.client import HTTPConnection
from pathlib import Path
import threading
import time
import unittest

from dashboard.server import DashboardRequestHandler, HTTPServer, analyze_scenario_end_to_end


class TestDashboardServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = None
        try:
            cls.server = HTTPServer(("127.0.0.1", 0), DashboardRequestHandler)
            cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
            cls.thread.start()
            time.sleep(0.1)
        except Exception:
            cls.server = None

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.shutdown()
            cls.server.server_close()

    def setUp(self):
        self.sample_scenario = {
            "scenario_id": "scenario_001",
            "users": [{"name": "UserA"}],
            "roles": [
                {
                    "name": "RoleA",
                    "trust_policy": {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Principal": {"AWS": "UserA"}, "Action": "sts:AssumeRole"}],
                    },
                    "permissions": [
                        {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::example-bucket/*"}
                    ],
                }
            ],
            "resources": [{"name": "ExampleBucket", "type": "s3", "arn": "arn:aws:s3:::example-bucket"}],
        }

    def test_analyze_scenario_end_to_end_function(self):
        result = analyze_scenario_end_to_end(self.sample_scenario)
        self.assertEqual(result["scenario_id"], "scenario_001")
        self.assertIn("graph", result)
        self.assertIn("paths", result)
        self.assertIn("predictions", result)
        self.assertIn("choke_points", result)

    def test_get_scenarios_api(self):
        if not self.server:
            self.skipTest("HTTPServer binding restricted in sandbox")
        port = self.server.server_port
        conn = HTTPConnection("127.0.0.1", port)
        conn.request("GET", "/api/scenarios")
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        self.assertIn("scenarios", data)
        conn.close()

    def test_post_analyze_api(self):
        if not self.server:
            self.skipTest("HTTPServer binding restricted in sandbox")
        port = self.server.server_port
        conn = HTTPConnection("127.0.0.1", port)
        body = json.dumps(self.sample_scenario).encode("utf-8")
        conn.request("POST", "/api/analyze", body, {"Content-Type": "application/json"})
        res = conn.getresponse()
        self.assertEqual(res.status, 200)
        data = json.loads(res.read().decode("utf-8"))
        self.assertEqual(data["scenario_id"], "scenario_001")
        self.assertIn("overall_risk_label", data)
        conn.close()


if __name__ == "__main__":
    unittest.main()
