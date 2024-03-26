"""Override module config for cveticket package."""
# noinspection PyUnresolvedReferences
from security.config import *

GITLAB_ISSUE_ASSIGNEES = os.environ["GITLAB_ISSUE_ASSIGNEES"]
CVE_PATH = os.environ["CVE_PATH"]
CI_JOB_URL = os.environ["CI_JOB_URL"]
SONAR_TOKEN = os.environ.get("SONAR_TOKEN", "")
FORCE_REOPEN = bool(os.environ.get("FORCE_REOPEN", 0))

for var_name, env_var in [
    ("APP_NAME", APP_NAME),
    ("GITLAB_ISSUE_ASSIGNEES", GITLAB_ISSUE_ASSIGNEES),
    ("CVE_PATH", CVE_PATH),
]:
    if not env_var:
        raise InternalErrorNoRecovery("ENV " + var_name + " was not declared.")

SEARCH_COMMENT_START = "Auto-generated by [" + APP_NAME + "]"
SCHEDULED_REOPENING_LABEL_NAME = "scheduled_reopening"
DESIGNATED_TEAM = "T1"
