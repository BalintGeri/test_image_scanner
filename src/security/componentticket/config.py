"""Override module config for componentticket package."""
# noinspection PyUnresolvedReferences
from security.config import *

COMPONENT_TICKET_APP_NAME = "security-component"
COMPONENT_TICKET_PREFIX = "[" + COMPONENT_TICKET_APP_NAME + "] "
COMPONENT_TICKET_ADD_LABELS = COMPONENT_TICKET_APP_NAME + ",T1"
GITLAB_ISSUE_ASSIGNEES = ""  # TODO
REMOVE_LABELS_ON_APPEND = ["Released"]
