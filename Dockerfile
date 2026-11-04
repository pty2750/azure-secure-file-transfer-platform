FROM mcr.microsoft.com/azure-functions/python:4-python3.11

ENV AzureWebJobsScriptRoot=/home/site/wwwroot \
    AzureFunctionsJobHost__Logging__Console__IsEnabled=true \
    CLAMDSCAN_PATH=/usr/bin/clamdscan \
    CLAMD_CONFIG_PATH=/etc/clamav/clamd.conf

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       clamav \
       clamav-daemon \
       clamdscan \
       ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY function_app/requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY function_app/ /home/site/wwwroot/
COPY src/ /home/site/src/


COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh

CMD ["/usr/local/bin/docker-entrypoint.sh"]

HEALTHCHECK --interval=30s --timeout=10s --start-period=120s --retries=3 CMD curl --fail --silent http://localhost:80/api/health > /dev/null || exit 1
