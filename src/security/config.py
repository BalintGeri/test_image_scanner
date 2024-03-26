"""Module for configuration and constants."""
import os

from security.ErrorTypes import InternalErrorNoRecovery
from security.GitlabAPI import GitLabAPI

APP_NAME = os.environ.get("APP_NAME")
GITLAB_URL = os.environ["GITLAB_URL"]
GITLAB_ISSUE_REPO_TARGET = os.environ["GITLAB_ISSUE_REPO_TARGET"]
GITLAB_ISSUE_CREATE_TOKEN = os.environ["GITLAB_ISSUE_CREATE_TOKEN"]

for var_name, env_var in [
    ("GITLAB_URL", GITLAB_URL),
    ("GITLAB_ISSUE_REPO_TARGET", GITLAB_ISSUE_REPO_TARGET),
    ("GITLAB_ISSUE_CREATE_TOKEN", GITLAB_ISSUE_CREATE_TOKEN),
]:
    if not env_var:
        raise InternalErrorNoRecovery("ENV " + var_name + " was not declared.")

FORCE_CLOSE_LABEL = "Closed"
PRIORITY_LABEL_PREFIX = "priority::"

api = GitLabAPI(GITLAB_ISSUE_CREATE_TOKEN, "https://" + GITLAB_URL, GITLAB_ISSUE_REPO_TARGET)
