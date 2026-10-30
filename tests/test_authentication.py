import base64
import json
import os
import unittest
from unittest.mock import patch

from src.authentication import authorize_request


class MockRequest:
    def __init__(self, headers=None):
        self.headers = headers or {}


def create_principal_header(claims, user_id="test-user"):
    principal = {
        "user_id": user_id,
        "claims": claims,
    }

    encoded = base64.b64encode(
        json.dumps(principal).encode("utf-8")
    ).decode("utf-8")

    return encoded


class AuthenticationTests(unittest.TestCase):

    @patch.dict(os.environ, {"AUTH_MODE": "development"})
    def test_development_mode_allows_request(self):
        request = MockRequest()

        authorized, status_code = authorize_request(request)

        self.assertTrue(authorized)
        self.assertIsNone(status_code)

    @patch.dict(os.environ, {"AUTH_MODE": "easyauth"})
    def test_missing_principal_returns_401(self):
        request = MockRequest()

        authorized, status_code = authorize_request(request)

        self.assertFalse(authorized)
        self.assertEqual(status_code, 401)

    @patch.dict(os.environ, {"AUTH_MODE": "easyauth"})
    def test_invalid_principal_returns_401(self):
        request = MockRequest({
            "X-MS-CLIENT-PRINCIPAL": "not-valid-base64"
        })

        authorized, status_code = authorize_request(request)

        self.assertFalse(authorized)
        self.assertEqual(status_code, 401)

    @patch.dict(os.environ, {"AUTH_MODE": "easyauth"})
    def test_valid_identity_without_role_returns_403(self):
        principal = create_principal_header(
            [{"typ": "name", "val": "Test User"}]
        )
        request = MockRequest({
            "X-MS-CLIENT-PRINCIPAL": principal
        })

        authorized, status_code = authorize_request(request)

        self.assertFalse(authorized)
        self.assertEqual(status_code, 403)

    @patch.dict(os.environ, {"AUTH_MODE": "easyauth"})
    def test_required_role_allows_request(self):
        principal = create_principal_header([
            {"typ": "roles", "val": "FileUploader"}
        ])
        request = MockRequest({
            "X-MS-CLIENT-PRINCIPAL": principal
        })

        authorized, status_code = authorize_request(request)

        self.assertTrue(authorized)
        self.assertIsNone(status_code)

    @patch.dict(os.environ, {"AUTH_MODE": "easyauth"})
    def test_wrong_role_returns_403(self):
        principal = create_principal_header([
            {"typ": "roles", "val": "Administrator"}
        ])
        request = MockRequest({
            "X-MS-CLIENT-PRINCIPAL": principal
        })

        authorized, status_code = authorize_request(request)

        self.assertFalse(authorized)
        self.assertEqual(status_code, 403)

    @patch.dict(os.environ, {"AUTH_MODE": "unsupported"})
    def test_unsupported_auth_mode_returns_503(self):
        request = MockRequest()

        authorized, status_code = authorize_request(request)

        self.assertFalse(authorized)
        self.assertEqual(status_code, 503)


if __name__ == "__main__":
    unittest.main()