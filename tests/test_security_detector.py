import json
import unittest
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SIMULATED_FILE = BASE_DIR / "data" / "simulated_security_events.json"


class TestSecurityDetector(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        with open(SIMULATED_FILE, "r", encoding="utf-8") as file:
            cls.events = json.load(file)["Records"]

    def test_simulated_events_loaded(self):
        """Check that all four simulated events are loaded."""
        self.assertEqual(len(self.events), 4)

    def test_failed_console_login(self):
        """Check that the failed login event exists."""
        matches = [
            event for event in self.events
            if event.get("eventName") == "ConsoleLogin"
            and event.get("responseElements", {}).get("ConsoleLogin") == "Failure"
        ]
        self.assertEqual(len(matches), 1)

    def test_unauthorised_api_call(self):
        """Check that an AccessDenied event exists."""
        matches = [
            event for event in self.events
            if event.get("errorCode") == "AccessDenied"
        ]
        self.assertEqual(len(matches), 1)

    def test_sensitive_iam_change(self):
        """Check that an access key creation event exists."""
        matches = [
            event for event in self.events
            if event.get("eventName") == "CreateAccessKey"
        ]
        self.assertEqual(len(matches), 1)

    def test_normal_activity(self):
        """Check that the normal EC2 event exists."""
        matches = [
            event for event in self.events
            if event.get("eventName") == "DescribeInstances"
        ]
        self.assertEqual(len(matches), 1)
    

    def test_detector_finds_three_threats(self):
        """The detector should identify three security threats."""
        from unittest.mock import patch
        from src.security_detector import detect_threats

        with patch("builtins.print"):
            alerts = detect_threats()

        self.assertEqual(len(alerts), 3)

    def test_detector_failed_login_severity(self):
        """Failed console logins should be MEDIUM severity."""
        from unittest.mock import patch
        from src.security_detector import detect_threats

        with patch("builtins.print"):
            alerts = detect_threats()

        login_alert = next(
            alert for alert in alerts
            if alert["event_name"] == "ConsoleLogin"
        )

        self.assertEqual(login_alert["severity"], "MEDIUM")
        self.assertEqual(login_alert["threat"], "Failed AWS Console Login")

    def test_detector_high_severity_threats(self):
        """Unauthorised API calls and IAM changes should be HIGH."""
        from unittest.mock import patch
        from src.security_detector import detect_threats

        with patch("builtins.print"):
            alerts = detect_threats()

        high_alerts = [
            alert for alert in alerts
            if alert["severity"] == "HIGH"
        ]

        self.assertEqual(len(high_alerts), 2)
        self.assertEqual(
            {alert["event_name"] for alert in high_alerts},
            {"StopLogging", "CreateAccessKey"}
        )

    def test_detector_ignores_normal_activity(self):
        """Normal EC2 activity should not generate an alert."""
        from unittest.mock import patch
        from src.security_detector import detect_threats

        with patch("builtins.print"):
            alerts = detect_threats()

        event_names = [alert["event_name"] for alert in alerts]

        self.assertNotIn("DescribeInstances", event_names)



if __name__ == "__main__":
    unittest.main()
