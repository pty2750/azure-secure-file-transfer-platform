
import json
import unittest
import uuid

from azure.storage.blob import BlobServiceClient
from src.audit_logger import write_audit_event

STORAGE_CONNECTION_STRING = "UseDevelopmentStorage=true"
STORAGE_API_VERSION = "2026-06-06"
AUDIT_CONTAINER_NAME = "audit-logs"


class TestAuditLogger(unittest.TestCase):

    def test_audit_event_is_persisted(self):
        filename = f"audit_test_{uuid.uuid4().hex}.csv"

        event = write_audit_event(
            event_type="automated_test",
            filename=filename,
            outcome="success",
            details={"test": True},
        )

        service = BlobServiceClient.from_connection_string(
            STORAGE_CONNECTION_STRING,
            api_version=STORAGE_API_VERSION,
        )

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

            self.assertEqual(stored_event["event_id"], event["event_id"])
            self.assertEqual(stored_event["event_type"], "automated_test")
            self.assertEqual(stored_event["filename"], filename)
            self.assertEqual(stored_event["outcome"], "success")
            self.assertEqual(stored_event["details"], {"test": True})
            self.assertTrue(stored_event["timestamp_utc"].endswith("+00:00"))

        finally:
            service.close()


if __name__ == "__main__":
    unittest.main()
