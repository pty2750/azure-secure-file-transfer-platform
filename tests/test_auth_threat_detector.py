import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from azure.core.exceptions import ResourceExistsError

from src.auth_threat_detector import detect_repeated_authentication_failures


class FakeBlobClient:
    def __init__(self, content):
        self.content = content

    def download_blob(self):
        return SimpleNamespace(readall=lambda: self.content)


class FakeContainer:
    def __init__(self, events):
        self.events = {}
        for index, event in enumerate(events):
            timestamp = datetime.fromisoformat(event["timestamp_utc"])
            name = f"{timestamp:%Y/%m/%d}/{index}.json"
            self.events[name] = json.dumps(event).encode()

    def list_blobs(self, name_starts_with):
        return [
            SimpleNamespace(name=name)
            for name in self.events
            if name.startswith(name_starts_with)
        ]

    def get_blob_client(self, name):
        return FakeBlobClient(self.events[name])


class ThreatDetectorTests(unittest.TestCase):
    NOW = datetime(2026, 11, 3, 12, 0, tzinfo=timezone.utc)

    def make_event(self, event_type, minutes_ago):
        return {
            "event_type": event_type,
            "timestamp_utc": (self.NOW - timedelta(minutes=minutes_ago)).isoformat(),
        }

    def run_detection(self, events, write_side_effect=None):
        service = MagicMock()
        service.get_container_client.return_value = FakeContainer(events)
        with patch(
            "src.auth_threat_detector.get_blob_service_client", return_value=service
        ), patch(
            "src.auth_threat_detector.write_audit_event", side_effect=write_side_effect
        ) as writer:
            result = detect_repeated_authentication_failures(now=self.NOW)
        service.close.assert_called_once()
        return result, writer

    def test_four_failures_do_not_trigger(self):
        events = [self.make_event("authentication_failed", i) for i in range(1, 5)]
        result, writer = self.run_detection(events)
        self.assertIsNone(result)
        writer.assert_not_called()

    def test_five_failures_trigger_critical_alert(self):
        events = [self.make_event("authentication_failed", i) for i in range(5)]
        _, writer = self.run_detection(events)
        self.assertEqual(writer.call_count, 1)
        kwargs = writer.call_args.kwargs
        self.assertEqual(kwargs["event_type"], "repeated_authentication_failures")
        self.assertEqual(kwargs["severity"], "CRITICAL")
        self.assertEqual(kwargs["details"]["failed_attempts_last_5_minutes"], 5)

    def test_non_auth_and_old_failures_ignored(self):
        events = [self.make_event("authentication_failed", i) for i in range(4)]
        events += [
            self.make_event("upload_rejected", 1),
            self.make_event("authentication_failed", 6),
            self.make_event("authentication_configuration_error", 1),
        ]
        _, writer = self.run_detection(events)
        writer.assert_not_called()

    def test_403_denials_are_counted(self):
        events = [self.make_event("authorization_denied", i) for i in range(5)]
        _, writer = self.run_detection(events)
        writer.assert_called_once()

    def test_duplicate_alert_is_not_error(self):
        events = [self.make_event("authentication_failed", i) for i in range(5)]
        result, writer = self.run_detection(
            events, write_side_effect=ResourceExistsError("already created")
        )
        self.assertIsNone(result)
        writer.assert_called_once()

    def test_persistent_id_is_stable_in_same_bucket(self):
        events = [self.make_event("authentication_failed", i) for i in range(5)]
        _, first = self.run_detection(events)
        _, second = self.run_detection(events)
        self.assertEqual(first.call_args.kwargs["event_id"],
                         second.call_args.kwargs["event_id"])


if __name__ == "__main__":
    unittest.main()
