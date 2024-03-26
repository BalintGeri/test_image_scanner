"""Datastructure for CVE."""
import logging

from security.CVE import CVE as PCVE
from security.cveticket.Component import Component
from security.Ticket import Ticket

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class CVE(PCVE):
    """Represents a CVE."""

    def __init__(
        self,
        name: str,
        severity: str,
        description: str,
        url: str,
        labels: str | None,
        components: list[Component],
        ticket: Ticket | None = None,
        source: int | None = None,
    ):
        """Initialise an instance."""
        super().__init__(name, severity, ticket, source)
        self.description: str = description
        self.url: str = url
        self.labels: str = labels or ""
        self.components: list[Component] = components
