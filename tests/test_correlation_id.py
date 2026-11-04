
import unittest
import uuid
from unittest.mock import patch

import azure.functions as func

from function_app import function_app as app_module


class TestCorrelationId(unittest.TestCase):

    def create_request(self, headers=None, params=None, body=b""):
        """Create a test HTTP request."""

        return func.HttpRequest(
            method="GET",
            url="http://localhost/api/health",
            headers=headers or {},
            params=params or {},
            route_params={},
            body=body,
        )

    def test_missing_correlation_id_generates_uuid(self):
        request = self.create_request()

        response = app_module.health(request)

        correlation_id = response.headers.get(
            "X-Correlation-ID"
        )

        self.assertIsNotNone(correlation_id)

        # Confirm the generated value is a valid UUID.
        parsed_id = uuid.UUID(correlation_id)

        self.assertEqual(
            str(parsed_id),
            correlation_id,
        )

    def test_valid_client_correlation_id_is_preserved(self):
        supplied_id = str(uuid.uuid4())

        request = self.create_request(
            headers={
                "X-Correlation-ID": supplied_id,
            }
        )

        response = app_module.health(request)

        self.assertEqual(
            response.headers.get("X-Correlation-ID"),
            supplied_id,
        )

    def test_invalid_client_correlation_id_is_replaced(self):
        request = self.create_request(
            headers={
                "X-Correlation-ID": "invalid-correlation-id",
            }
        )

        response = app_module.health(request)

        returned_id = response.headers.get(
            "X-Correlation-ID"
        )

        self.assertIsNotNone(returned_id)
        self.assertNotEqual(
            returned_id,
            "invalid-correlation-id",
        )

        # Confirm the replacement is a valid UUID.
        uuid.UUID(returned_id)

    @patch.object(app_module, "write_audit_event")
    @patch.object(app_module, "validate_file")
    @patch.object(app_module, "authorize_request")
    def test_audit_event_uses_response_correlation_id(
        self,
        mock_authorize,
        mock_validate,
        mock_write_audit,
    ):
        supplied_id = str(uuid.uuid4())

        request = func.HttpRequest(
            method="POST",
            url="http://localhost/api/validate",
            headers={
                "X-Correlation-ID": supplied_id,
            },
            params={
                "filename": "correlation_test.csv",
            },
            route_params={},
            body=b"name,age\nJohn,25",
        )

        mock_authorize.return_value = (True, 200)

        mock_validate.return_value = {
            "filename": "correlation_test.csv",
            "accepted": True,
            "status": "accepted",
            "errors": [],
            "size_bytes": 17,
            "sha256": "test-checksum",
        }

        response = app_module.validate_upload(request)

        response_id = response.headers.get(
            "X-Correlation-ID"
        )

        self.assertEqual(response_id, supplied_id)

        mock_write_audit.assert_called_once()

        audit_arguments = mock_write_audit.call_args.kwargs

        self.assertEqual(
            audit_arguments["event_type"],
            "validation_accepted",
        )

        self.assertEqual(
            audit_arguments["filename"],
            "correlation_test.csv",
        )

        self.assertEqual(
            audit_arguments["correlation_id"],
            response_id,
        )


if __name__ == "__main__":
    unittest.main()
