import logging
import os

from azure.storage.blob import BlobServiceClient

logger = logging.getLogger("secure_file_transfer.storage")

# Keep the API version that has already been tested with Azurite.
STORAGE_API_VERSION = "2026-06-06"

# Default local development configuration.
DEFAULT_STORAGE_CONNECTION_STRING = "UseDevelopmentStorage=true"


def get_blob_service_client() -> BlobServiceClient:
    """
    Create a Blob Storage service client.

    Supports:
    1. Local development using Azurite.
    2. Azure deployment using Managed Identity.
    3. Azure Storage connection strings.
    """

    storage_auth_mode = os.getenv(
        "STORAGE_AUTH_MODE",
        "connection_string",
    ).strip().lower()

    if storage_auth_mode == "managed_identity":
        account_url = os.getenv("STORAGE_ACCOUNT_URL")

        if not account_url:
            raise ValueError(
                "STORAGE_ACCOUNT_URL must be configured "
                "when using Managed Identity."
            )

        try:
            from azure.identity import DefaultAzureCredential
        except ImportError as exc:
            raise RuntimeError(
                "azure-identity is required for Managed Identity."
            ) from exc

        credential = DefaultAzureCredential()

        logger.info(
            "storage_authentication_mode=managed_identity"
        )

        return BlobServiceClient(
            account_url=account_url,
            credential=credential,
            api_version=STORAGE_API_VERSION,
        )

    if storage_auth_mode == "connection_string":
        connection_string = os.getenv(
            "STORAGE_CONNECTION_STRING",
            DEFAULT_STORAGE_CONNECTION_STRING,
        )

        logger.info(
            "storage_authentication_mode=connection_string"
        )

        return BlobServiceClient.from_connection_string(
            connection_string,
            api_version=STORAGE_API_VERSION,
        )

    raise ValueError(
        f"Unsupported STORAGE_AUTH_MODE: {storage_auth_mode}"
    )