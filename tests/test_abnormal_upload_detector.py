"""Unit tests for abnormal upload activity detection."""

import json
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from azure.core.exceptions import ResourceExistsError

from src.abnormal_upload_detector import (
    ALERT_EVENT,
    THRESHOLD,
    UPLOAD_EVENTS,
    detect_abnormal_upload_activity,
)


class AbnormalUploadDetectorTests(unittest.TestCase):

    def setUp(self):
        self.now = datetime(2026, 11, 3, 22, 23, tzinfo=timezone.utc)

    def make_event(self, event_type, timestamp=None):
        return {
            "event_type": event_type,
            "timestamp_utc": (timestamp or self.now).isoformat(),
        }

    def run_detector(self, events, now=None, duplicate=False):
        service = MagicMock()
        container = service.get_container_client.return_value

        container.list_blobs.side_effect = lambda name_starts_with: [
            SimpleNamespace(name=f"{name_starts_with}{i}.json")
            for i in range(len(events))
            if events[i]["timestamp_utc"][:10].replace("-", "/")
            == name_starts_with[:10]
        ]

        def get_blob(name):
            index = int(name.rsplit("/", 1)[-1].replace(".json", ""))
            blob_client = MagicMock()
            blob_client.download_blob.return_value.readall.return_value = (
                json.dumps(events[index]).encode("utf-8")
            )
            return blob_client

        container.get_blob_client.side_effect = get_blob

        with patch(
            "src.abnormal_upload_detector.get_blob_service_client",
            return_value=service,
        ), patch(
            "src.abnormal_upload_detector.write_audit_event"
        ) as write_event:

            if duplicate:
                write_event.side_effect = ResourceExistsError(
                    message="Already exists"
                )
            else:
                write_event.return_value = {
                    "event_type": ALERT_EVENT,
                    "severity": "WARNING",
                }

            result = detect_abnormal_upload_activity(
                correlation_id="test-correlation",
                now=now or self.now,
            )

            return result, write_event, service

    def test_nineteen_uploads_do_not_trigger(self):
        events = [
            self.make_event("upload_succeeded")
            for _ in range(THRESHOLD - 1)
        ]

        result, write_event, _ = self.run_detector(events)

        self.assertIsNone(result)
        write_event.assert_not_called()

    def test_twenty_uploads_trigger_warning(self):
        events = [
            self.make_event("upload_succeeded")
            for _ in range(THRESHOLD)
        ]

        result, write_event, service = self.run_detector(events)

        self.assertEqual(result["event_type"], ALERT_EVENT)
        self.assertEqual(result["severity"], "WARNING")
        self.assertEqual(
            write_event.call_args.kwargs["details"][
                "upload_attempts_last_5_minutes"
            ],
            THRESHOLD,
        )
        self.assertEqual(
            write_event.call_args.kwargs["severity"],
            "WARNING",
        )
        service.close.assert_called_once()

    def test_all_upload_outcomes_are_counted(self):
        events = [
            self.make_event(event_type)
            for event_type in UPLOAD_EVENTS
        ]

        events = (events * 4)[:THRESHOLD]

        result, _, _ = self.run_detector(events)

        self.assertIsNotNone(result)

    def test_old_events_are_ignored(self):
        events = [
            self.make_event(
                "upload_succeeded",
                self.now - timedelta(minutes=6),
            )
            for _ in range(THRESHOLD)
        ]

        result, write_event, _ = self.run_detector(events)

        self.assertIsNone(result)
        write_event.assert_not_called()

    def test_unrelated_events_are_ignored(self):
        events = [
            self.make_event("validation_accepted")
            for _ in range(THRESHOLD)
        ]

        result, write_event, _ = self.run_detector(events)

        self.assertIsNone(result)
        write_event.assert_not_called()

    def test_duplicate_alert_is_ignored(self):
        events = [
            self.make_event("upload_rejected")
            for _ in range(THRESHOLD)
        ]

        result, _, _ = self.run_detector(events, duplicate=True)

        self.assertIsNone(result)

    def test_naive_datetime_is_rejected(self):
        with self.assertRaises(ValueError):
            detect_abnormal_upload_activity(
                now=datetime(2026, 11, 3, 22, 23)
            )


if __name__ == "__main__":
    unittest.main()
