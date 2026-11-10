import json
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "data" / "simulated_security_events.json"

SENSITIVE_IAM_ACTIONS = {
    "CreateAccessKey",
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateUser",
    "UpdateAssumeRolePolicy",
}


def detect_threats():
    """Analyse CloudTrail events for potential security threats."""

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    events = data.get("Records", [])
    alerts = []

    for event in events:
        event_name = event.get("eventName", "")
        error_code = event.get("errorCode", "")
        event_source = event.get("eventSource", "")
        response = event.get("responseElements") or {}

        threat = None
        severity = None

        if (
            event_name == "ConsoleLogin"
            and response.get("ConsoleLogin") == "Failure"
        ):
            threat = "Failed AWS Console Login"
            severity = "MEDIUM"

        elif (
            "AccessDenied" in error_code
            or "UnauthorizedOperation" in error_code
        ):
            threat = "Unauthorised AWS API Call"
            severity = "HIGH"

        elif (
            event_source == "iam.amazonaws.com"
            and event_name in SENSITIVE_IAM_ACTIONS
            and not error_code
        ):
            threat = "Security-Sensitive IAM Change"
            severity = "HIGH"

        if threat:
            alerts.append({
                "event_name": event_name,
                "threat": threat,
                "severity": severity,
                "source_ip": event.get("sourceIPAddress", "Unknown"),
                "timestamp": event.get("eventTime", "Unknown"),
            })

    print("\nAWS CLOUD SECURITY DETECTION RESULTS")
    print("=" * 45)
    print(f"Total events analysed: {len(events)}")
    print(f"Security alerts detected: {len(alerts)}")

    for index, alert in enumerate(alerts, start=1):
        print(f"\nAlert {index}")
        print("-" * 35)
        print(f"Threat: {alert['threat']}")
        print(f"Event: {alert['event_name']}")
        print(f"Severity: {alert['severity']}")
        print(f"Source IP: {alert['source_ip']}")
        print(f"Timestamp: {alert['timestamp']}")

    if not alerts:
        print("\nNo suspicious activity detected.")

    return alerts


if __name__ == "__main__":
    detect_threats()
