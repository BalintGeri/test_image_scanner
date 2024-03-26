"""Module for datastructures and methods to order CVE lists."""

import logging

from security.CVE import CVE

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


# Constant for unknown severity
undefined = "UNDEFINED"
# order of severity from up to low.
ordered_severity: list[str] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", undefined]
# Translates undefined priority to default.
ordered_priority: dict[None, int] = {None: 1000}


def group_by_severity(c: CVE) -> int:
    """Reduces an CVE to its severity."""
    try:
        return ordered_severity.index(c.severity.upper())
    except ValueError:
        log.warning("Unknown severity: " + str(c.severity))
        return ordered_severity.index(undefined)


def group_by_priority(c: CVE) -> int:
    """Reduces an CVE to its priority."""
    return c.ticket.priority if c.ticket and c.ticket.priority else ordered_priority[None]
