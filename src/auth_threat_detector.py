"""Detect a service-wide burst of failed authentication using persisted audit blobs.

This detection intentionally aggregates 401/403 events across the service. It does
not attribute anonymous requests to a particular user or IP address: a client-
provided identity or forwarded address would be spoofable in local development.
"""

import json
import logging
import uuid
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import ResourceExistsError

from src.audit_logger import AUDIT_CONTAINER_NAME, write_audit_event
from src.storage_config import get_blob_service_client

logger = logging.getLogger("secure_file_transfer.auth_threat_detector")

WINDOW = timedelta(minutes=5)
THRESHOLD = 5
FAILURE_EVENTS = {"authentication_failed", "authorization_denied"}
ALERT_EVENT = "repeated_authentication_failures"


def detect_repeated_authentication_failures(correlation_id=None, now=None):
    """Store one critical alert per UTC 5-minute bucket once 5 failures occur.

    Counts persisted events within the preceding 5 minutes, including the event
    just recorded. The alert's deterministic blob ID deduplicates across hosts.
    Returns the alert dictionary, or None when below threshold/already alerted.
    Storage errors propagate so the calling API can log but not hide its 401/403.
    """
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    now = now.astimezone(timezone.utc)
    cutoff = now - WINDOW
    service = get_blob_service_client()
    failures = 0

    try:
        container = service.get_container_client(AUDIT_CONTAINER_NAME)
        prefixes = {f"{day:%Y/%m/%d}/" for day in (cutoff, now)}

        for prefix in sorted(prefixes):
            for blob in container.list_blobs(name_starts_with=prefix):
                # Audit events are immutable small JSON documents. Ignore alerts
                # and all non-authentication events when counting.
                raw = container.get_blob_client(blob.name).download_blob().readall()
                event = json.loads(raw)
                if event.get("event_type") not in FAILURE_EVENTS:
                    continue
                timestamp = datetime.fromisoformat(event["timestamp_utc"])
                if timestamp.tzinfo is None:
                    continue
                if cutoff <= timestamp.astimezone(timezone.utc) <= now:
                    failures += 1
    finally:
        service.close()

    if failures < THRESHOLD:
        return None

    # A stable UUID ensures that concurrent instances don't create duplicate
    # alerts for the same five-minute UTC bucket.
    bucket_start = now.replace(
        minute=(now.minute // 5) * 5, second=0, microsecond=0
    )
    event_id = str(uuid.uuid5(uuid.NAMESPACE_URL, f"{ALERT_EVENT}:{bucket_start.isoformat()}"))

    try:
        return write_audit_event(
            event_type=ALERT_EVENT,
            filename="(authentication)",
            outcome="alert",
            details={
                "failed_attempts_last_5_minutes": failures,
                "threshold": THRESHOLD,
                "window_minutes": 5,
                "scope": "service_wide",
                "bucket_start_utc": bucket_start.isoformat(),
            },
            correlation_id=correlation_id,
            severity="CRITICAL",
            event_id=event_id,
        )
    except ResourceExistsError:
        logger.info("authentication_failure_alert_already_recorded bucket=%s", bucket_start)
        return None
