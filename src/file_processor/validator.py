import hashlib
import re
from pathlib import PurePosixPath

# Configurable validation settings
ALLOWED_EXTENSIONS = {".pdf", ".csv", ".txt"}
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_FILENAME_LENGTH = 255

# Permit letters, numbers, underscores, hyphens, and periods.
# Filenames must begin with a letter or number.
VALID_FILENAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")

# Windows reserved device names (case-insensitive).
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def is_valid_filename(filename: str) -> bool:
    """Return whether a filename is safe for storage."""

    if not isinstance(filename, str) or not filename:
        return False

    if len(filename) > MAX_FILENAME_LENGTH:
        return False

    if filename in {".", ".."}:
        return False

    # Reject path separators and consecutive periods.
    if "/" in filename or "\\" in filename or ".." in filename:
        return False

    # Reject filenames ending in a period.
    if filename.endswith("."):
        return False

    # Allow only the explicitly permitted characters.
    if not VALID_FILENAME_PATTERN.fullmatch(filename):
        return False

    # Reject Windows reserved device names, including names with extensions.
    filename_stem = filename.split(".", 1)[0].upper()
    if filename_stem in WINDOWS_RESERVED_NAMES:
        return False

    return True


def validate_file(filename: str, content: bytes) -> dict:
    """Validate a file and return its processing result."""

    errors = []

    # Validate the filename.
    if not is_valid_filename(filename):
        errors.append("Invalid filename.")

    # Validate the extension.
    suffix = PurePosixPath(filename).suffix.lower() if isinstance(filename, str) else ""
    if suffix not in ALLOWED_EXTENSIONS:
        errors.append("File extension is not allowed.")

    # Validate file size.
    if len(content) > MAX_FILE_SIZE_BYTES:
        errors.append("File exceeds the configured size limit.")

    # Calculate checksum even for rejected content, if supplied.
    checksum = hashlib.sha256(content).hexdigest()

    return {
        "filename": filename,
        "accepted": len(errors) == 0,
        "status": "accepted" if not errors else "rejected",
        "errors": errors,
        "size_bytes": len(content),
        "sha256": checksum,
    }
