"""Datastructure for CVE."""
import json
import logging

from security import config
from security.AppSource import app_source_translator, AppSource
from security.ErrorTypes import GitLabApiFetchError
from security.GitLabApiTypes import FindIssue
from security.IssueHelper import check_issue_labels_contain, get_issue_label_startswith
from security.Ticket import Ticket, TicketFactory

log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)


class CVE:
    """Represents a CVE."""

    def __init__(self, name: str, severity: str, ticket: Ticket | None = None, source: int | None = None):
        """Initialise an instance."""
        self.name: str = name
        self.severity: str = severity
        self.ticket: Ticket | None = ticket
        self.source: AppSource | None = AppSource(source) if source is not None else None

    def __str__(self):
        return str("CVE(" + str((self.name, str(self.ticket), str(self.source))) + ")")

    def __repr__(self):
        return str(self)

    def __hash__(self):
        return hash((self.name, self.source))

    def __eq__(self, other: "CVE"):
        if isinstance(other, CVE):
            return self.name == other.name and (
                self.source is None or other.source is None or self.source == other.source
            )
        return False

    def load_ticket(self, cached=True) -> Ticket | None:
        """Find ticket for CVE and add ticket_id, severity and priority to datastructure."""
        if not cached or self.ticket is None:
            try:
                issue = self.get_issue()
            except ImportError as e:
                self.ticket = None
                log.warning(e)
                return self.ticket

            factory: TicketFactory = TicketFactory()
            factory.iid = int(issue["iid"])
            factory.is_closed = issue["state"] == "closed"
            factory.forced_closed = check_issue_labels_contain(config.FORCE_CLOSE_LABEL, issue)
            prio = get_issue_label_startswith(config.PRIORITY_LABEL_PREFIX, issue)
            if prio:
                try:
                    factory.priority = int(prio)
                except ValueError:
                    log.warning("Found non-int priority label: " + str(prio))
                    pass

            self.ticket = factory.build()
        return self.ticket

    def get_issue(self) -> FindIssue:
        """Find ticket for CVE."""
        try:
            app_name = app_source_translator[self.source]
        except KeyError:
            raise ImportError('Source of ticket "' + self.name + '" is unknown. Source: ' + str(self.source))

        title = "[" + app_name + "] " + self.name
        try:
            issues_found = config.api.find_issue(title, log_level=logging.DEBUG)
        except GitLabApiFetchError:
            raise ImportError('Ticket for CVE "' + title + '" not found. Fetch failed.')

        if len(issues_found) == 0:
            raise ImportError('Ticket for CVE "' + title + '" not found.')

        if len(issues_found) > 1:
            # Reduce list to exact matches
            issues_found = [issue for issue in issues_found if title.strip() == str(issue["title"]).strip()]
            log.debug("Reduce issues_found list to " + str(len(issues_found)))
        if len(issues_found) > 1:
            raise ImportError('Abort because there are too many issues with the title "' + title + '"')
        issue = issues_found[0]
        if not check_issue_labels_contain(app_name, issue):
            raise ImportError(
                'Abort because issue labels found do not contain app_name ("'
                + app_name
                + '"). Labels: '
                + str(issue["labels"])
            )
        return issue

    def is_ticket_open_or_none(self) -> bool:
        """
        Check if any ticket is open.

        :return: True if ticket is open or no ticket found
        """
        return self.ticket is None or not self.ticket.is_closed


class CVEEncoder(json.JSONEncoder):
    """JSONEncoder with Implementation for CVE."""

    def default(self, o):
        """
        Extend default behaviour to recognize CVE objects.

        :return: a serializable object for o if possible, otherwise it call the superclass
        """
        if isinstance(o, CVE):
            return {"name": o.name, "severity": o.severity, "source": o.source}
        # call base class implementation which takes care of
        # raising exceptions for unsupported types
        return json.JSONEncoder.default(self, o)
