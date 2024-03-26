"""Module for issue help functions."""

from security.ErrorTypes import InternalErrorNoRecovery
from security.GitLabApiTypes import Issue


def check_issue_labels_contain(label: str, issue: Issue) -> bool:
    """Check if issue has specific label."""
    if not label or not issue:
        raise InternalErrorNoRecovery("Parameters missing.")
    labels = issue.get("labels", [])
    if label in labels:
        return True
    return False


def get_issue_label_startswith(label_prefix: str, issue: Issue) -> str | None:
    """Retrieve label of issue by prefix or None if not found."""
    if not label_prefix or not issue:
        raise InternalErrorNoRecovery("Parameters missing.")
    labels = issue.get("labels", [])
    for label in labels:
        if label.startswith(label_prefix):
            return label.partition(label_prefix)[2]
    return None
