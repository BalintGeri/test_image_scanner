"""Override module IssueHelper for componentticket package."""
from security.componentticket import config
from security.IssueHelper import *


def get_instructions_for_labels_removal(ticket: Issue) -> dict[str, str]:
    """Return ready-to-use params dict with remove_labels data."""
    instructions = {}
    for label_for_removal in config.REMOVE_LABELS_ON_APPEND:
        if check_issue_labels_contain(label_for_removal, ticket):
            if instructions.get("remove_labels") is None:
                instructions["remove_labels"] = label_for_removal
            else:
                instructions["remove_labels"] += "," + label_for_removal
    return instructions
