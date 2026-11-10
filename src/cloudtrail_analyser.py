
import json
from pathlib import Path

# Locate the downloaded AWS CloudTrail log
BASE_DIR = Path(__file__).resolve().parent.parent
LOG_FILE = BASE_DIR / "data" / "event_history.json"


def analyse_cloudtrail():
    """Read and analyse AWS CloudTrail events."""

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    events = data.get("Records", [])

    print("\nAWS CLOUD SECURITY MONITORING LAB")
    print("=" * 45)
    print(f"Total CloudTrail events: {len(events)}")

    for index, event in enumerate(events, start=1):
        print(f"\nEvent {index}")
        print("-" * 35)
        print(f"Event name: {event.get('eventName', 'Unknown')}")
        print(f"Event time: {event.get('eventTime', 'Unknown')}")
        print(f"Event source: {event.get('eventSource', 'Unknown')}")
        print(f"AWS region: {event.get('awsRegion', 'Unknown')}")
        print(f"Source IP: {event.get('sourceIPAddress', 'Unknown')}")
        print(f"Error code: {event.get('errorCode', 'None')}")


if __name__ == "__main__":
    analyse_cloudtrail()
