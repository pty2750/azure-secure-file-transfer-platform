
import unittest
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from azure.core.exceptions import ResourceExistsError

from src.upload_threat_detector import (
    detect_repeated_upload_rejections,
)


class UploadThreatDetectorTests(unittest.TestCase):

    def setUp(self):
        self.now = datetime(
            2026, 11, 3, 21, 0, tzinfo=timezone.utc
        )

    def make_event(self, event_type, minutes_ago=1):
        return {
            "event_type": event_type,
            "timestamp_utc": (
                self.now - timedelta(minutes=minutes_ago)
            ).isoformat(),
        }

    def run_detector(self, events):
        service = MagicMock()
        container = service.get_container_client.return_value

        container.list_blobs.return_value = [
            SimpleNamespace(name=f"2026/11/03/{i}.json")
            for i in range(len(events))
        ]

        def get_blob(name):
            index = int(name.rsplit("/", 1)[-1].split(".")[0])
            blob = MagicMock()
            blob.download_blob.return_value.readall.return_value = (
                __import__("json").dumps(events[index]).encode()
            )
            return blob

        container.get_blob_client.side_effect = get_blob

        with patch(
            "src.upload_threat_detector.get_blob_service_client",
            return_value=service,
        ), patch(
            "src.upload_threat_detector.write_audit_event"
        ) as write_event:
            write_event.return_value = {"outcome": "alert"}

            result = detect_repeated_upload_rejections(
                now=self.now
            )

            return result, write_event

    def test_four_rejections_do_not_trigger(self):
        events = [
            self.make_event("upload_rejected")
            for _ in range(4)
        ]

        result, write_event = self.run_detector(events)

        self.assertIsNone(result)
        write_event.assert_not_called()

    def test_five_rejections_trigger_warning(self):
        events = [
            self.make_event("upload_rejected")
            for _ in range(5)
        ]

        result, write_event = self.run_detector(events)

        self.assertEqual(result["outcome"], "alert")
        self.assertEqual(
            write_event.call_args.kwargs["severity"],
            "WARNING",
        )
        self.assertEqual(
            write_event.call_args.kwargs["event_type"],
            "repeated_upload_rejections",
        )

    def test_old_rejections_are_ignored(self):
        events = [
            self.make_event("upload_rejected", minutes_ago=10)
            for _ in range(5)
        ]

        result, write_event = self.run_detector(events)

        self.assertIsNone(result)
        write_event.assert_not_called()

    def test_unrelated_events_are_ignored(self):
        events = [
            self.make_event("authentication_failed")
            for _ in range(5)
        ]

        result, write_event = self.run_detector(events)

        self.assertIsNone(result)
        write_event.assert_not_called()

    def test_duplicate_alert_is_ignored(self):
        service = MagicMock()
        container = service.get_container_client.return_value

        container.list_blobs.return_value = [
            SimpleNamespace(name=f"2026/11/03/{i}.json")
            for i in range(5)
        ]

        events = [
            self.make_event("upload_rejected")
            for _ in range(5)
        ]

        def get_blob(name):
            index = int(name.rsplit("/", 1)[-1].split(".")[0])
            blob = MagicMock()
            blob.download_blob.return_value.readall.return_value = (
                __import__("json").dumps(events[index]).encode()
            )
            return blob

        container.get_blob_client.side_effect = get_blob

        with patch(
            "src.upload_threat_detector.get_blob_service_client",
            return_value=service,
        ), patch(
            "src.upload_threat_detector.write_audit_event",
            side_effect=ResourceExistsError(
                "Alert already exists"
            ),
        ):
            result = detect_repeated_upload_rejections(
                now=self.now
            )

        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
