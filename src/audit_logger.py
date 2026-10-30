
import json
import logging
import uuid

from datetime import datetime, timezone

from azure.core.exceptions import ResourceExistsError
from azure.storage.blob import BlobServiceClient


logger = logging.getLogger("secure_file_transfer.audit")

STORAGE_CONNECTION_STRING = "UseDevelopmentStorage=true"
STORAGE_API_VERSION = "2026-06-06"
AUDIT_CONTAINER_NAME = "audit-logs"


def write_audit_event(
    event_type: str,
    filename: str,
    outcome: str,
    details: dict | None = None,
) -> dict:
    """Persist one structured audit event in Blob Storage."""

    timestamp = datetime.now(timezone.utc)
    event_id = str(uuid.uuid4())

    event = {
        "event_id": event_id,
        "timestamp_utc": timestamp.isoformat(),
        "event_type": event_type,
        "filename": filename,
        "outcome": outcome,
        "details": details or {},
    }

    service = BlobServiceClient.from_connection_string(
        STORAGE_CONNECTION_STRING,
        api_version=STORAGE_API_VERSION,
    )

    try:
        container = service.get_container_client(
            AUDIT_CONTAINER_NAME
        )

        try:
            container.create_container()
        except ResourceExistsError:
            pass

        blob_name = (
            f"{timestamp:%Y/%m/%d}/{event_id}.json"
        )

        container.upload_blob(
            name=blob_name,
            data=json.dumps(event, separators=(",", ":")),
            overwrite=False,
        )

        logger.info(
            "audit_event_persisted event_id=%s event_type=%s outcome=%s",
            event_id,
            event_type,
            outcome,
        )

        return event

    except Exception:
        logger.exception(
            "audit_event_persistence_failed event_id=%s event_type=%s",
            event_id,
            event_type,
        )
        raise

    finally:
        service.close()
