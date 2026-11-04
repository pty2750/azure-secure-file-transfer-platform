#!/bin/sh
set -eu

echo "Preparing ClamAV..."

mkdir -p /var/run/clamav /var/lib/clamav
chown clamav:clamav /var/run/clamav /var/lib/clamav

echo "Updating ClamAV malware signatures..."
freshclam

echo "Starting ClamAV daemon..."
clamd --config-file=/etc/clamav/clamd.conf

echo "Waiting for ClamAV to become ready..."

attempt=0
until clamdscan --config-file=/etc/clamav/clamd.conf --ping=1 >/dev/null 2>&1; do
    attempt=$((attempt + 1))

    if [ "$attempt" -ge 90 ]; then
        echo "ClamAV did not become ready."
        exit 1
    fi

    sleep 2
done

echo "ClamAV is ready."
echo "Starting Azure Functions..."

exec /opt/startup/start_nonappservice.sh
