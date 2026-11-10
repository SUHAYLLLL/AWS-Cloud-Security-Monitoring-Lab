import csv
import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "data" / "simulated_security_events.json"
OUTPUT_FILE = BASE_DIR / "alerts" / "aws_security_alerts.csv"

SENSITIVE_IAM_ACTIONS = {
    "CreateAccessKey",
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateUser",
    "UpdateAssumeRolePolicy",
}


def generate_alerts():
    """Analyse CloudTrail events and export security alerts to CSV."""

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    alerts = []

    for event in data.get("Records", []):
        event_name = event.get("eventName", "")
        error_code = event.get("errorCode", "")
        response = event.get("responseElements") or {}

        threat = None
        severity = None

        if (
            event_name == "ConsoleLogin"
            and response.get("ConsoleLogin") == "Failure"
        ):
            threat = "Failed AWS Console Login"
            severity = "MEDIUM"

        elif error_code in {"AccessDenied", "AccessDeniedException"}:
            threat = "Unauthorised AWS API Call"
            severity = "HIGH"

        elif event_name in SENSITIVE_IAM_ACTIONS:
            threat = "Security-Sensitive IAM Change"
            severity = "HIGH"

        if threat:
            alerts.append({
                "timestamp": event.get("eventTime", "Unknown"),
                "event_name": event_name,
                "threat": threat,
                "severity": severity,
                "source_ip": event.get("sourceIPAddress", "Unknown"),
                "aws_region": event.get("awsRegion", "Unknown"),
            })

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp",
                "event_name",
                "threat",
                "severity",
                "source_ip",
                "aws_region",
            ],
        )
        writer.writeheader()
        writer.writerows(alerts)

    print("\nAWS CLOUD SECURITY ALERT REPORT")
    print("=" * 45)
    print(f"Total events analysed: {len(data.get('Records', []))}")
    print(f"Security alerts generated: {len(alerts)}")
    print(f"Report saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    generate_alerts()
