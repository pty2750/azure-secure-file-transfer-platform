
import json
import unittest
import uuid

from src.audit_logger import (
    determine_severity,
    write_audit_event,
)
from src.storage_config import get_blob_service_client


AUDIT_CONTAINER_NAME = "audit-logs"


class TestAuditLogger(unittest.TestCase):

    def test_audit_event_is_persisted(self):
        filename = f"audit_test_{uuid.uuid4().hex}.csv"
        correlation_id = str(uuid.uuid4())

        event = write_audit_event(
            event_type="automated_test",
            filename=filename,
            outcome="success",
            details={"test": True},
            correlation_id=correlation_id,
        )

        service = get_blob_service_client()

        try:
            container = service.get_container_client(
                AUDIT_CONTAINER_NAME
            )

            blob_name = (
                f"{event['timestamp_utc'][:4]}/"
                f"{event['timestamp_utc'][5:7]}/"
                f"{event['timestamp_utc'][8:10]}/"
                f"{event['event_id']}.json"
            )

            stored_event = json.loads(
                container.download_blob(blob_name).readall()
            )

            self.assertEqual(
                stored_event["event_id"],
                event["event_id"],
            )
            self.assertEqual(
                stored_event["correlation_id"],
                correlation_id,
            )
            self.assertEqual(
                stored_event["event_type"],
                "automated_test",
            )
            self.assertEqual(
                stored_event["filename"],
                filename,
            )
            self.assertEqual(
                stored_event["outcome"],
                "success",
            )
            self.assertEqual(
                stored_event["details"],
                {"test": True},
            )
            self.assertEqual(
                stored_event["severity"],
                "INFO",
            )
            self.assertTrue(
                stored_event["timestamp_utc"].endswith("+00:00")
            )

        finally:
            service.close()

    def test_missing_correlation_id_is_generated(self):
        event = write_audit_event(
            event_type="automated_test",
            filename="test.csv",
            outcome="success",
        )

        self.assertTrue(
            uuid.UUID(event["correlation_id"])
        )

    def test_invalid_correlation_id_is_rejected(self):
        with self.assertRaises(ValueError):
            write_audit_event(
                event_type="automated_test",
                filename="test.csv",
                outcome="success",
                correlation_id="invalid-id",
            )

    def test_empty_event_type_is_rejected(self):
        with self.assertRaises(ValueError):
            write_audit_event(
                event_type="",
                filename="test.csv",
                outcome="success",
            )

    def test_invalid_details_are_rejected(self):
        with self.assertRaises(ValueError):
            write_audit_event(
                event_type="automated_test",
                filename="test.csv",
                outcome="success",
                details="not-a-dictionary",
            )

    def test_malware_detection_is_critical(self):
        self.assertEqual(
            determine_severity("malware_detected", "rejected"),
            "CRITICAL",
        )

    def test_malware_scan_failure_is_error(self):
        self.assertEqual(
            determine_severity("malware_scan_failed", "failed"),
            "ERROR",
        )

    def test_storage_failure_is_error(self):
        self.assertEqual(
            determine_severity("upload_storage_failed", "failed"),
            "ERROR",
        )

    def test_rejected_event_is_warning(self):
        self.assertEqual(
            determine_severity("validation_rejected", "rejected"),
            "WARNING",
        )

    def test_successful_event_is_info(self):
        self.assertEqual(
            determine_severity("validation_accepted", "accepted"),
            "INFO",
        )

    def test_explicit_severity_is_preserved(self):
        event = write_audit_event(
            event_type="automated_test",
            filename="test.csv",
            outcome="success",
            severity="critical",
        )

        self.assertEqual(event["severity"], "CRITICAL")

    def test_invalid_severity_is_rejected(self):
        with self.assertRaises(ValueError):
            write_audit_event(
                event_type="automated_test",
                filename="test.csv",
                outcome="success",
                severity="HIGH",
            )


if __name__ == "__main__":
    unittest.main()
