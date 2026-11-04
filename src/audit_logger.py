
import json
import logging
import uuid
from datetime import datetime, timezone

from azure.core.exceptions import ResourceExistsError

from src.storage_config import get_blob_service_client


logger = logging.getLogger("secure_file_transfer.audit")

AUDIT_CONTAINER_NAME = "audit-logs"

VALID_SEVERITIES = {
    "INFO",
    "WARNING",
    "ERROR",
    "CRITICAL",
}


def determine_severity(event_type, outcome):
    """Determine the default severity for an audit event."""

    if event_type == "malware_detected":
        return "CRITICAL"

    if event_type in {
        "malware_scan_failed",
        "upload_storage_failed",
        "authentication_configuration_error",
    }:
        return "ERROR"

    if outcome in {"rejected", "failed"}:
        return "WARNING"

    return "INFO"


def write_audit_event(
    event_type: str,
    filename: str,
    outcome: str,
    details: dict | None = None,
    correlation_id: str | None = None,
    severity: str | None = None,
    event_id: str | None = None,
) -> dict:
    """
    Persist one structured audit event in Blob Storage.
    """

    if not isinstance(event_type, str) or not event_type.strip():
        raise ValueError("event_type must be a non-empty string.")

    if not isinstance(filename, str) or not filename.strip():
        raise ValueError("filename must be a non-empty string.")

    if not isinstance(outcome, str) or not outcome.strip():
        raise ValueError("outcome must be a non-empty string.")

    if details is not None and not isinstance(details, dict):
        raise ValueError("details must be a dictionary.")

    if correlation_id is None:
        correlation_id = str(uuid.uuid4())
    else:
        try:
            correlation_id = str(uuid.UUID(correlation_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError(
                "correlation_id must be a valid UUID."
            ) from exc

    if severity is None:
        severity = determine_severity(event_type, outcome)
    else:
        if not isinstance(severity, str):
            raise ValueError("severity must be a string.")

        severity = severity.upper()

        if severity not in VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {sorted(VALID_SEVERITIES)}."
            )

    timestamp = datetime.now(timezone.utc)

    if event_id is None:
        event_id = str(uuid.uuid4())
    else:
        try:
            event_id = str(uuid.UUID(event_id))
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("event_id must be a valid UUID.") from exc

    event = {
        "event_id": event_id,
        "correlation_id": correlation_id,
        "timestamp_utc": timestamp.isoformat(),
        "event_type": event_type,
        "filename": filename,
        "outcome": outcome,
        "severity": severity,
        "details": details or {},
    }

    service = get_blob_service_client()

    try:
        container = service.get_container_client(
            AUDIT_CONTAINER_NAME
        )

        try:
            container.create_container()
        except ResourceExistsError:
            pass

        blob_name = f"{timestamp:%Y/%m/%d}/{event_id}.json"

        container.upload_blob(
            name=blob_name,
            data=json.dumps(event, separators=(",", ":")),
            overwrite=False,
        )

        logger.log(
            getattr(logging, severity),
            "audit_event_persisted "
            "event_id=%s correlation_id=%s "
            "event_type=%s outcome=%s severity=%s",
            event_id,
            correlation_id,
            event_type,
            outcome,
            severity,
        )

        return event

    except ResourceExistsError:
        logger.info(
            "audit_event_already_exists "
            "event_id=%s correlation_id=%s event_type=%s",
            event_id,
            correlation_id,
            event_type,
        )
        raise

    except Exception:
        logger.exception(
            "audit_event_persistence_failed "
            "event_id=%s correlation_id=%s event_type=%s",
            event_id,
            correlation_id,
            event_type,
        )
        raise

    finally:
        service.close()
