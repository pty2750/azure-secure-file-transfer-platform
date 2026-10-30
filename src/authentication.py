import base64
import json
import logging
import os

logger = logging.getLogger("secure_file_transfer.authentication")


def authorize_request(req, required_role="FileUploader"):
    """Authorize a request using local development mode or Azure Easy Auth."""

    auth_mode = os.getenv("AUTH_MODE", "easyauth").strip().lower()

    if auth_mode == "development":
        return True, None

    if auth_mode != "easyauth":
        logger.error("Unsupported AUTH_MODE: %s", auth_mode)
        return False, 503

    principal_header = req.headers.get("X-MS-CLIENT-PRINCIPAL")

    if not principal_header:
        return False, 401

    try:
        decoded = base64.b64decode(principal_header, validate=True)
        principal = json.loads(decoded.decode("utf-8"))

        if not isinstance(principal, dict):
            return False, 401

        claims = principal.get("claims", [])

        if not isinstance(claims, list):
            return False, 401

        user_id = principal.get("user_id")

        has_identity_claim = any(
            isinstance(claim, dict)
            and claim.get("typ") in ("oid", "sub")
            and claim.get("val")
            for claim in claims
        )

        if not user_id and not has_identity_claim:
            return False, 401

        roles = {
            claim.get("val")
            for claim in claims
            if isinstance(claim, dict)
            and claim.get("typ") in (
                "roles",
                "role",
                "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",
            )
        }

        if required_role not in roles:
            return False, 403

        return True, None

    except (ValueError, TypeError, UnicodeDecodeError):
        logger.warning("Invalid X-MS-CLIENT-PRINCIPAL header")
        return False, 401
