import json
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid

from azure.storage.blob import BlobServiceClient


BASE_URL = "http://localhost:7071/api"
STORAGE_CONNECTION_STRING = "UseDevelopmentStorage=true"
STORAGE_API_VERSION = "2026-06-06"
CONTAINER_NAME = "accepted-files"


def api_request(method, path, body=b"", content_type="text/plain"):
    """Send an HTTP request and return its status code and response body."""
    request = urllib.request.Request(
        f"{BASE_URL}/{path}",
        data=body if method != "GET" else None,
        method=method,
        headers={"Content-Type": content_type},
    )

    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, response.read().decode("utf-8")
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read().decode("utf-8")


class TestFileTransferAPI(unittest.TestCase):

    def test_health_endpoint(self):
        status, body = api_request("GET", "health")

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["status"], "healthy")

    def test_validate_accepts_csv(self):
        path = "validate?" + urllib.parse.urlencode(
            {"filename": "api_test.csv"}
        )

        status, body = api_request(
            "POST", path, b"id,amount\n1,100", "text/csv"
        )

        result = json.loads(body)
        self.assertEqual(status, 200)
        self.assertTrue(result["accepted"])
        self.assertEqual(result["status"], "accepted")

    def test_validate_rejects_exe(self):
        path = "validate?" + urllib.parse.urlencode(
            {"filename": "malware.exe"}
        )

        status, body = api_request("POST", path, b"test content")

        self.assertEqual(status, 400)
        self.assertFalse(json.loads(body)["accepted"])

    def test_validate_rejects_unsafe_filenames(self):
        unsafe_filenames = (
            "../secret.txt",
            "..\\..\\secret.txt",
            "CON.txt",
            "NUL.csv",
            "payment..csv",
            "a" * 252 + ".csv",
        )

        for filename in unsafe_filenames:
            with self.subTest(filename=filename):
                path = "validate?" + urllib.parse.urlencode(
                    {"filename": filename}
                )

                status, body = api_request(
                    "POST", path, b"test content"
                )

                self.assertEqual(status, 400, body)
                result = json.loads(body)
                self.assertFalse(result["accepted"])
                self.assertIn("Invalid filename.", result["errors"])

    def test_validate_rejects_pdf_with_invalid_content(self):
        path = "validate?" + urllib.parse.urlencode(
            {"filename": "invoice.pdf"}
        )

        status, body = api_request(
            "POST", path, b"This is ordinary text", "application/pdf"
        )

        result = json.loads(body)
        self.assertEqual(status, 400, body)
        self.assertFalse(result["accepted"])
        self.assertIn(
            "File content does not match the PDF format.",
            result["errors"],
        )

    def test_validate_rejects_csv_with_binary_content(self):
        path = "validate?" + urllib.parse.urlencode(
            {"filename": "payment.csv"}
        )

        status, body = api_request(
            "POST", path, b"id,amount\x00\x01", "text/csv"
        )

        result = json.loads(body)
        self.assertEqual(status, 400, body)
        self.assertFalse(result["accepted"])
        self.assertIn(
            "Text files must not contain null bytes.",
            result["errors"],
        )

    def test_validate_rejects_csv_with_invalid_utf8(self):
        path = "validate?" + urllib.parse.urlencode(
            {"filename": "payment.csv"}
        )

        status, body = api_request(
            "POST", path, b"\xff\xfe\xfa", "text/csv"
        )

        result = json.loads(body)
        self.assertEqual(status, 400, body)
        self.assertFalse(result["accepted"])
        self.assertIn(
            "Text files must contain valid UTF-8 content.",
            result["errors"],
        )

    def test_upload_requires_filename(self):
        status, body = api_request("POST", "upload", b"test content")

        self.assertEqual(status, 400)
        self.assertIn("filename", json.loads(body)["error"].lower())

    def test_upload_rejects_disallowed_extension(self):
        path = "upload?" + urllib.parse.urlencode(
            {"filename": "malware.exe"}
        )

        status, body = api_request("POST", path, b"test content")

        self.assertEqual(status, 400)
        self.assertFalse(json.loads(body)["accepted"])

    def test_upload_rejects_unsafe_filenames(self):
        unsafe_filenames = (
            "../secret.txt",
            "..\\..\\secret.txt",
            "CON.txt",
            "NUL.csv",
            "payment..csv",
            "a" * 252 + ".csv",
        )

        for filename in unsafe_filenames:
            with self.subTest(filename=filename):
                path = "upload?" + urllib.parse.urlencode(
                    {"filename": filename}
                )

                status, body = api_request(
                    "POST", path, b"test content"
                )

                self.assertEqual(status, 400, body)
                result = json.loads(body)
                self.assertFalse(result["accepted"])
                self.assertIn("Invalid filename.", result["errors"])

    def test_upload_rejects_pdf_with_invalid_content(self):
        path = "upload?" + urllib.parse.urlencode(
            {"filename": "invoice.pdf"}
        )

        status, body = api_request(
            "POST", path, b"This is ordinary text", "application/pdf"
        )

        result = json.loads(body)
        self.assertEqual(status, 400, body)
        self.assertFalse(result["accepted"])
        self.assertIn(
            "File content does not match the PDF format.",
            result["errors"],
        )

    def test_upload_rejects_csv_with_binary_content(self):
        path = "upload?" + urllib.parse.urlencode(
            {"filename": "payment.csv"}
        )

        status, body = api_request(
            "POST", path, b"id,amount\x00\x01", "text/csv"
        )

        result = json.loads(body)
        self.assertEqual(status, 400, body)
        self.assertFalse(result["accepted"])
        self.assertIn(
            "Text files must not contain null bytes.",
            result["errors"],
        )

    def test_upload_rejects_csv_with_invalid_utf8(self):
        path = "upload?" + urllib.parse.urlencode(
            {"filename": "payment.csv"}
        )

        status, body = api_request(
            "POST", path, b"\xff\xfe\xfa", "text/csv"
        )

        result = json.loads(body)
        self.assertEqual(status, 400, body)
        self.assertFalse(result["accepted"])
        self.assertIn(
            "Text files must contain valid UTF-8 content.",
            result["errors"],
        )

    def test_upload_stores_file_and_rejects_duplicate(self):
        # Use a unique name so the test can be run repeatedly.
        filename = f"api_test_{uuid.uuid4().hex}.csv"
        path = "upload?" + urllib.parse.urlencode(
            {"filename": filename}
        )
        content = b"id,amount\n1,250"

        service = BlobServiceClient.from_connection_string(
            STORAGE_CONNECTION_STRING,
            api_version=STORAGE_API_VERSION,
        )
        blob = service.get_container_client(
            CONTAINER_NAME
        ).get_blob_client(filename)

        try:
            # First upload should succeed.
            status, body = api_request(
                "POST", path, content, "text/csv"
            )

            self.assertEqual(status, 201, body)
            self.assertEqual(json.loads(body)["storage"], "uploaded")

            # Verify the file really exists in local Blob Storage.
            self.assertTrue(blob.exists())

            # Uploading the same filename again should return HTTP 409.
            duplicate_status, duplicate_body = api_request(
                "POST", path, content, "text/csv"
            )

            self.assertEqual(duplicate_status, 409, duplicate_body)
            self.assertIn(
                "already exists",
                json.loads(duplicate_body)["error"].lower(),
            )

        finally:
            # Remove only this test's file to keep future runs repeatable.
            if blob.exists():
                blob.delete_blob()
            service.close()


if __name__ == "__main__":
    unittest.main()
