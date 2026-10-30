import json
import logging
import os
import sys
from pathlib import Path

import azure.functions as func
from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobServiceClient

# Allow imports from the repository root.
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.file_processor.validator import validate_file
from src.audit_logger import write_audit_event
from src.malware_scanner import scan_file
from src.authentication import authorize_request

logger = logging.getLogger("secure_file_transfer")

app = func.FunctionApp(
    http_auth_level=func.AuthLevel.FUNCTION
)

STORAGE_CONNECTION_STRING = os.getenv(
    "STORAGE_CONNECTION_STRING",
    "UseDevelopmentStorage=true",
)

STORAGE_API_VERSION = "2026-06-06"
CONTAINER_NAME = "accepted-files"


def get_container_client():
    """Connect to the configured Blob Storage account."""
    service = BlobServiceClient.from_connection_string(
        STORAGE_CONNECTION_STRING,
        api_version=STORAGE_API_VERSION,
    )
    return service.get_container_client(CONTAINER_NAME)


def record_audit(event_type, filename, outcome, details=None):
    """Record an audit event without hiding the API result."""
    try:
        write_audit_event(
            event_type=event_type,
            filename=filename,
            outcome=outcome,
            details=details,
        )
    except Exception:
        logger.exception(
            "audit_record_failed event_type=%s filename=%r",
            event_type,
            filename,
        )


def authentication_response(status_code):
    """Build a consistent authentication error response."""
    if status_code == 401:
        message = "Authentication is required."
    elif status_code == 403:
        message = "You do not have permission to perform this action."
    else:
        message = "Authentication configuration is invalid."

    return func.HttpResponse(
        json.dumps({"error": message}),
        status_code=status_code,
        mimetype="application/json",
    )


@app.route(
    route="health",
    methods=["GET"],
    auth_level=func.AuthLevel.ANONYMOUS,
)
def health(req: func.HttpRequest) -> func.HttpResponse:
    """Return the basic service health status."""
    response = {
        "service": "secure-file-transfer-platform",
        "status": "healthy",
        "version": "1.0.0",
    }

    return func.HttpResponse(
        json.dumps(response),
        status_code=200,
        mimetype="application/json",
    )


@app.route(
    route="validate",
    methods=["POST"],
    auth_level=func.AuthLevel.ANONYMOUS,
)
def validate_upload(req: func.HttpRequest) -> func.HttpResponse:
    """Validate a file without storing it."""
    authorized, status_code = authorize_request(req)

    if not authorized:
        return authentication_response(status_code)

    filename = req.params.get("filename", "")
    content = req.get_body()

    if not filename:
        logger.warning("validation_rejected reason=missing_filename")

        record_audit(
            "validation_rejected",
            "(missing)",
            "rejected",
            {"reason": "missing_filename"},
        )

        return func.HttpResponse(
            json.dumps({
                "error": "Provide a filename query parameter."
            }),
            status_code=400,
            mimetype="application/json",
        )

    result = validate_file(filename, content)

    if not result["accepted"]:
        logger.warning(
            "validation_rejected filename=%r errors=%s",
            filename,
            result["errors"],
        )

        record_audit(
            "validation_rejected",
            filename,
            "rejected",
            {
                "errors": result["errors"],
                "size_bytes": result["size_bytes"],
                "sha256": result["sha256"],
            },
        )
    else:
        logger.info(
            "validation_accepted filename=%r size_bytes=%d sha256=%s",
            filename,
            result["size_bytes"],
            result["sha256"],
        )

        record_audit(
            "validation_accepted",
            filename,
            "accepted",
            {
                "size_bytes": result["size_bytes"],
                "sha256": result["sha256"],
            },
        )

    return func.HttpResponse(
        json.dumps(result),
        status_code=200 if result["accepted"] else 400,
        mimetype="application/json",
    )


@app.route(
    route="upload",
    methods=["POST"],
    auth_level=func.AuthLevel.ANONYMOUS,
)
def upload_file(req: func.HttpRequest) -> func.HttpResponse:
    """Validate, scan, and store an uploaded file."""
    authorized, status_code = authorize_request(req)

    if not authorized:
        return authentication_response(status_code)

    filename = req.params.get("filename", "")

    if not filename:
        logger.warning("upload_rejected reason=missing_filename")

        record_audit(
            "upload_rejected",
            "(missing)",
            "rejected",
            {"reason": "missing_filename"},
        )

        return func.HttpResponse(
            json.dumps({
                "error": "Provide a filename query parameter."
            }),
            status_code=400,
            mimetype="application/json",
        )

    content = req.get_body()

    logger.info(
        "upload_attempt filename=%r size_bytes=%d",
        filename,
        len(content),
    )

    # Step 1: Validate filename, extension, and file size.
    result = validate_file(filename, content)

    if not result["accepted"]:
        logger.warning(
            "upload_rejected filename=%r errors=%s",
            filename,
            result["errors"],
        )

        record_audit(
            "upload_rejected",
            filename,
            "rejected",
            {
                "errors": result["errors"],
                "size_bytes": result["size_bytes"],
                "sha256": result["sha256"],
            },
        )

        return func.HttpResponse(
            json.dumps(result),
            status_code=400,
            mimetype="application/json",
        )

    # Step 2: Scan the file before uploading it.
    try:
        scan_result = scan_file(content, filename)
        scan_status = scan_result.get("status")
    except Exception:
        logger.exception(
            "malware_scan_exception filename=%r",
            filename,
        )

        record_audit(
            "malware_scan_failed",
            filename,
            "failed",
            {
                "size_bytes": result["size_bytes"],
                "sha256": result["sha256"],
                "scan_status": "ERROR",
                "reason": "Unexpected scanner exception",
            },
        )

        return func.HttpResponse(
            json.dumps({
                "error": (
                    "Malware scanning is unavailable or failed. "
                    "The file was not uploaded."
                ),
                "scan_status": "ERROR",
            }),
            status_code=503,
            mimetype="application/json",
        )

    if scan_status == "INFECTED":
        logger.warning("malware_detected filename=%r", filename)

        record_audit(
            "malware_detected",
            filename,
            "rejected",
            {
                "size_bytes": result["size_bytes"],
                "sha256": result["sha256"],
                "scan_status": "INFECTED",
            },
        )

        return func.HttpResponse(
            json.dumps({
                "error": "File rejected because malware was detected.",
                "filename": filename,
                "scan_status": "INFECTED",
            }),
            status_code=400,
            mimetype="application/json",
        )

    # Only explicitly clean files can be stored.
    if scan_status != "CLEAN":
        logger.error(
            "malware_scan_failed filename=%r status=%r",
            filename,
            scan_status,
        )

        record_audit(
            "malware_scan_failed",
            filename,
            "failed",
            {
                "size_bytes": result["size_bytes"],
                "sha256": result["sha256"],
                "scan_status": scan_status or "UNKNOWN",
                "reason": scan_result.get(
                    "message",
                    "Unknown scan error",
                ),
            },
        )

        return func.HttpResponse(
            json.dumps({
                "error": (
                    "Malware scanning is unavailable or failed. "
                    "The file was not uploaded."
                ),
                "scan_status": "ERROR",
            }),
            status_code=503,
            mimetype="application/json",
        )

    # Step 3: Store only validated, clean files.
    try:
        container_client = get_container_client()
        blob_client = container_client.get_blob_client(filename)

        blob_client.upload_blob(
            content,
            overwrite=False,
        )

    except ResourceExistsError:
        logger.warning(
            "duplicate_upload filename=%r",
            filename,
        )

        record_audit(
            "duplicate_upload",
            filename,
            "rejected",
            {
                "reason": "filename_already_exists",
                "scan_status": "CLEAN",
            },
        )

        return func.HttpResponse(
            json.dumps({
                "error": "A file with this name already exists.",
                "filename": filename,
            }),
            status_code=409,
            mimetype="application/json",
        )

    except Exception:
        logger.exception(
            "upload_storage_failed filename=%r",
            filename,
        )

        record_audit(
            "upload_storage_failed",
            filename,
            "failed",
            {
                "reason": "storage_operation_failed",
                "scan_status": "CLEAN",
            },
        )

        return func.HttpResponse(
            json.dumps({
                "error": (
                    "File was validated and scanned, "
                    "but storage failed."
                )
            }),
            status_code=500,
            mimetype="application/json",
        )

    # Step 4: Record successful upload.
    logger.info(
        "upload_succeeded filename=%r size_bytes=%d sha256=%s",
        filename,
        result["size_bytes"],
        result["sha256"],
    )

    record_audit(
        "upload_succeeded",
        filename,
        "success",
        {
            "size_bytes": result["size_bytes"],
            "sha256": result["sha256"],
            "container": CONTAINER_NAME,
            "scan_status": "CLEAN",
        },
    )

    result["storage"] = "uploaded"
    result["container"] = CONTAINER_NAME
    result["malware_scan"] = "CLEAN"

    return func.HttpResponse(
        json.dumps(result),
        status_code=201,
        mimetype="application/json",
    )
