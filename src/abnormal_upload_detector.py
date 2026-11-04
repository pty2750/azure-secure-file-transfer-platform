"""Detect abnormal upload volume using persisted audit events."""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import ResourceExistsError

from src.audit_logger import AUDIT_CONTAINER_NAME, write_audit_event
from src.storage_config import get_blob_service_client

logger = logging.getLogger("secure_file_transfer.abnormal_upload_detector")

WINDOW = timedelta(minutes=5)
THRESHOLD = 20
ALERT_EVENT = "abnormal_upload_activity"

UPLOAD_EVENTS = {
    "upload_succeeded",
    "upload_rejected",
    "malware_detected",
    "malware_scan_failed",
    "duplicate_upload",
    "upload_storage_failed",
}


def detect_abnormal_upload_activity(correlation_id=None, now=None):
    """Alert when at least 20 upload outcomes occur within five minutes."""
    if now is None:
        now = datetime.now(timezone.utc)

    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    now = now.astimezone(timezone.utc)
    cutoff = now - WINDOW
    upload_count = 0

    service = get_blob_service_client()

    try:
        container = service.get_container_client(AUDIT_CONTAINER_NAME)

        prefixes = {
            f"{day:%Y/%m/%d}/"
            for day in (cutoff, now)
        }

        for prefix in sorted(prefixes):
            for blob in container.list_blobs(name_starts_with=prefix):
                raw = (
                    container.get_blob_client(blob.name)
                    .download_blob()
                    .readall()
                )
                event = json.loads(raw)

                if event.get("event_type") not in UPLOAD_EVENTS:
                    continue

                timestamp_value = event.get("timestamp_utc")
                if not timestamp_value:
                    continue

                timestamp = datetime.fromisoformat(timestamp_value)

                if timestamp.tzinfo is None:
                    continue

                timestamp = timestamp.astimezone(timezone.utc)

                if cutoff <= timestamp <= now:
                    upload_count += 1

    finally:
        service.close()

    if upload_count < THRESHOLD:
        return None

    bucket_start = now.replace(
        minute=(now.minute // 5) * 5,
        second=0,
        microsecond=0,
    )

    event_id = str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"{ALERT_EVENT}:{bucket_start.isoformat()}",
        )
    )

    try:
        return write_audit_event(
            event_type=ALERT_EVENT,
            filename="(multiple uploads)",
            outcome="alert",
            details={
                "upload_attempts_last_5_minutes": upload_count,
                "threshold": THRESHOLD,
                "window_minutes": 5,
                "scope": "service_wide",
                "bucket_start_utc": bucket_start.isoformat(),
            },
            correlation_id=correlation_id,
            severity="WARNING",
            event_id=event_id,
        )

    except ResourceExistsError:
        logger.info(
            "abnormal_upload_alert_already_recorded bucket=%s",
            bucket_start,
        )
        return None
