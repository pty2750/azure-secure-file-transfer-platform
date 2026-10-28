
import hashlib
import re
from pathlib import PurePosixPath

# Configurable validation settings
ALLOWED_EXTENSIONS = {".pdf", ".csv", ".txt"}
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

# Permit letters, numbers, underscores, hyphens, and periods.
# Reject path separators, control characters, and other symbols.
VALID_FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")


def validate_file(filename: str, content: bytes) -> dict:
    """Validate a file and return its processing result."""

    errors = []

    # Validate the filename
    if (
        not filename
        or filename in {".", ".."}
        or "/" in filename
        or "\\" in filename
        or not VALID_FILENAME_PATTERN.fullmatch(filename)
    ):
        errors.append("Invalid filename.")

    # Validate extension
    suffix = PurePosixPath(filename).suffix.lower() if filename else ""
    if suffix not in ALLOWED_EXTENSIONS:
        errors.append("File extension is not allowed.")

    # Validate size
    if len(content) > MAX_FILE_SIZE_BYTES:
        errors.append("File exceeds the configured size limit.")

    # Calculate checksum even for rejected content, if supplied
    checksum = hashlib.sha256(content).hexdigest()

    return {
        "filename": filename,
        "accepted": len(errors) == 0,
        "status": "accepted" if not errors else "rejected",
        "errors": errors,
        "size_bytes": len(content),
        "sha256": checksum,
    }
