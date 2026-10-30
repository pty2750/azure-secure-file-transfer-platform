
import unittest
from unittest.mock import MagicMock, patch

import azure.functions as func

from function_app import function_app as app_module


class TestUploadMalwareProtection(unittest.TestCase):
    def setUp(self):
        self.filename = "security_test.csv"
        self.content = b"id,amount\n1,100"

        self.request = func.HttpRequest(
            method="POST",
            url=f"http://localhost/api/upload?filename={self.filename}",
            headers={"Content-Type": "text/csv"},
            params={"filename": self.filename},
            route_params={},
            body=self.content,
        )

        self.container = MagicMock()
        self.blob = MagicMock()
        self.container.get_blob_client.return_value = self.blob

        self.container_patch = patch.object(
            app_module,
            "get_container_client",
            return_value=self.container,
        )
        self.audit_patch = patch.object(
            app_module,
            "record_audit",
        )

        self.container_patch.start()
        self.audit_patch.start()

        self.addCleanup(self.container_patch.stop)
        self.addCleanup(self.audit_patch.stop)

    @patch.object(
        app_module,
        "scan_file",
        return_value={
            "status": "CLEAN",
            "message": "No malware detected.",
        },
    )
    def test_clean_file_is_uploaded(self, mock_scan):
        response = app_module.upload_file(self.request)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(self.blob.upload_blob.call_count, 1)

        body = response.get_body().decode("utf-8")
        self.assertIn('"malware_scan": "CLEAN"', body)

        mock_scan.assert_called_once_with(
            self.content,
            self.filename,
        )

    @patch.object(
        app_module,
        "scan_file",
        return_value={
            "status": "INFECTED",
            "message": "Test detection.",
        },
    )
    def test_infected_file_is_rejected(self, mock_scan):
        response = app_module.upload_file(self.request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self.blob.upload_blob.call_count, 0)

        body = response.get_body().decode("utf-8")
        self.assertIn('"scan_status": "INFECTED"', body)

        app_module.record_audit.assert_any_call(
            "malware_detected",
            self.filename,
            "rejected",
            unittest.mock.ANY,
        )

    @patch.object(
        app_module,
        "scan_file",
        return_value={
            "status": "ERROR",
            "message": "Scanner unavailable.",
        },
    )
    def test_scanner_error_blocks_upload(self, mock_scan):
        response = app_module.upload_file(self.request)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.blob.upload_blob.call_count, 0)

        body = response.get_body().decode("utf-8")
        self.assertIn('"scan_status": "ERROR"', body)

        app_module.record_audit.assert_any_call(
            "malware_scan_failed",
            self.filename,
            "failed",
            unittest.mock.ANY,
        )

    @patch.object(
        app_module,
        "scan_file",
        side_effect=RuntimeError("Simulated scanner crash"),
    )
    def test_scanner_exception_does_not_upload_file(self, mock_scan):
        response = app_module.upload_file(self.request)

        self.assertEqual(response.status_code, 503)
        self.assertEqual(self.blob.upload_blob.call_count, 0)

        body = response.get_body().decode("utf-8")
        self.assertIn('"scan_status": "ERROR"', body)

        app_module.record_audit.assert_any_call(
            "malware_scan_failed",
            self.filename,
            "failed",
            unittest.mock.ANY,
        )

        mock_scan.assert_called_once_with(
            self.content,
            self.filename,
        )


if __name__ == "__main__":
    unittest.main()
