"""Datastructure for start-source."""
from enum import IntEnum


class AppSource(IntEnum):
    """Enum for apps."""

    IMAGE_SCANNER = 1
    SECURITY_CHECKER = 2


app_source_translator: dict[AppSource, str] = {
    AppSource.IMAGE_SCANNER: "image-scanner",
    AppSource.SECURITY_CHECKER: "security-checker",
}
