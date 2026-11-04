
"""Detect repeated rejected uploads using persisted audit events."""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import ResourceExistsError

from src.audit_logger import AUDIT_CONTAINER_NAME, write_audit_event
from src.storage_config import get_blob_service_client

logger = logging.getLogger("secure_file_transfer.upload_threat_detector")

WINDOW = timedelta(minutes=5)
THRESHOLD = 5
REJECTION_EVENT = "upload_rejected"
ALERT_EVENT = "repeated_upload_rejections"


def detect_repeated_upload_rejections(correlation_id=None, now=None):
    """Create a WARNING alert after five rejected uploads in five minutes."""
    now = now or datetime.now(timezone.utc)

    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    now = now.astimezone(timezone.utc)
    cutoff = now - WINDOW
    rejected_count = 0

    service = get_blob_service_client()

    try:
        container = service.get_container_client(AUDIT_CONTAINER_NAME)

        prefixes = {
            f"{day:%Y/%m/%d}/"
            for day in (cutoff, now)
        }

        for prefix in sorted(prefixes):
            for blob in container.list_blobs(name_starts_with=prefix):
                raw = container.get_blob_client(
                    blob.name
                ).download_blob().readall()

                event = json.loads(raw)

                if event.get("event_type") != REJECTION_EVENT:
                    continue

                timestamp = datetime.fromisoformat(
                    event["timestamp_utc"]
                )

                if timestamp.tzinfo is None:
                    continue

                timestamp = timestamp.astimezone(timezone.utc)

                if cutoff <= timestamp <= now:
                    rejected_count += 1

    finally:
        service.close()

    if rejected_count < THRESHOLD:
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
                "rejected_uploads_last_5_minutes": rejected_count,
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
            "upload_rejection_alert_already_recorded bucket=%s",
            bucket_start,
        )
        return None
