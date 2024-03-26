"""Module for requests to GitLab API."""
import logging
import time

import requests
from requests import Response, Session

from security.ErrorTypes import GitLabApiFetchError, GitLabApiTypeError
from security.GitLabApiTypes import FindIssue, FullIssue, IssueComment, IssueLink, Project, RepositoryTree

log = logging.getLogger(__name__)
log.setLevel(logging.INFO)


class GitLabAPI:
    """
    The ApiClient for the GitLab Connection.

    I decided against an existing package (https://python-gitlab.readthedocs.io/)
    because I think that issues cannot be searched for there solely on the basis of the title.
    """

    def __init__(self, token, url, issue_repo_id):
        """Initialise an instance."""
        self.session: Session = requests.Session()
        self.session.headers.update({"PRIVATE-TOKEN": token})
        self.url = url
        self.issue_repo_id = issue_repo_id

    def fetch(
        self,
        action_msg: str,
        url: str,
        params=None,
        headers=None,
        action="get",
        log_level_success: int = logging.INFO,
        log_level_fail: int = logging.WARNING,
        suppress_error_msg: list[int] | None = None,
    ) -> Response:
        """
        Single request to API.

        Retries on errors.

        :param action_msg: Description for the call
        :param url: Target URL
        :param params: Request params
        :param headers: HTTP header
        :param action: HTTP verb
        :param log_level_success: Level for success messages
        :param log_level_fail: Level for fail messages
        :param suppress_error_msg: List of HTTP status codes to suppress log messages
        :return: API response
        """
        retries_no = 1
        retry_delay = 1
        for _ in range(0, retries_no):
            try:
                if action.lower() == "post":
                    response = self.session.post(url, data=params, headers=headers)
                elif action.lower() == "put":
                    response = self.session.put(url, data=params, headers=headers)
                elif action.lower() == "delete":
                    response = self.session.delete(url, params=params, headers=headers)
                else:
                    response = self.session.get("https://git.primeo-energie.ch/api/v4/projects/3/issues", params=params, headers=headers)
                response.raise_for_status()
                log.log(log_level_success, action_msg + " done.")
                return response
            except requests.exceptions.RequestException as e:
                if not suppress_error_msg or e.response is None or e.response.status_code not in suppress_error_msg:
                    log.log(log_level_fail, action_msg + " failed. Error: " + str(e))
                if e.response is not None:
                    match e.response.status_code:
                        case 429:
                            # 429 Too many requests
                            log.info("Increase retry_delay to 60s.")
                            retry_delay = 60
                        case 409:
                            # 409 Conflict
                            raise GitLabApiFetchError(str(e))
                        case 404:
                            print("hello")
                            print("url is" + url)
                        case _:
                            pass
            time.sleep(retry_delay)

        log.error("Failed after " + str(retries_no) + " retries")
        raise GitLabApiFetchError()

    def fetch_page(
        self,
        action_msg: str,
        url: str,
        params=None,
        headers=None,
        action="get",
        page=1,
        log_level_success: int = logging.INFO,
        log_level_fail: int = logging.WARNING,
        suppress_error_msg: list[int] | None = None,
    ) -> list[dict[str, any]]:
        """
        All-page request to API.

        Only works for list responses. Retries on errors.

        :param action_msg: Description for the call
        :param url: Target URL
        :param params: Request params
        :param headers: HTTP header
        :param action: HTTP verb
        :param page:
        :param log_level_success: Level for success messages
        :param log_level_fail: Level for fail messages
        :param suppress_error_msg: List of HTTP status codes to suppress log messages
        :return: API response
        """
        if params is None:
            params = {}
        params["page"] = page
        params["per_page"] = 100
        response = self.fetch(
            action_msg,
            url,
            params,
            headers,
            action,
            log_level_success=log_level_success,
            log_level_fail=log_level_fail,
            suppress_error_msg=suppress_error_msg,
        )
        response_json = response.json()
        if isinstance(response_json, list):
            if int(response.headers.get("x-page", 0)) < int(response.headers.get("x-total-pages", 0)):
                return response_json + self.fetch_page(
                    action_msg,
                    "https://git.primeo-energie.ch/api/v4/projects/3/issues",
                    params,
                    headers,
                    action,
                    page + 1,
                    log_level_success=log_level_success,
                    log_level_fail=log_level_fail,
                )
            return response_json
        raise GitLabApiTypeError("Type was not list.")

    def create_link_between_issues(
        self,
        issue_iid: int,
        link_issue_iid: int,
        log_level_success: int = logging.INFO,
        log_level_fail: int = logging.WARNING,
    ) -> IssueLink:
        """
        Creates a two-way relation between two issues.

        See https://docs.gitlab.com/ee/api/issue_links.html#create-an-issue-link.
        """
        return self.fetch(
            "Issue link creating",
            self.url + "/api/v4/projects/" + self.issue_repo_id + "/issues/" + str(issue_iid) + "/links",
            params={"target_project_id": self.issue_repo_id, "target_issue_iid": str(link_issue_iid)},
            action="POST",
            log_level_success=log_level_success,
            log_level_fail=log_level_fail,
            suppress_error_msg=[409],
        ).json()

    def find_issue(self, title: str, log_level: int = logging.INFO) -> list[FindIssue]:
        """
        Get a list of a project’s issues matching the search criteria.

        See https://docs.gitlab.com/ee/api/issues#list-project-issues.
        """
        return self.fetch_page(
            "Issues pulling",
            self.url + "/api/v4/projects/" + "3" + "/issues",
            params={"search": title, "in": "title"},
            log_level_success=log_level,
        )

    def create_issue(self, params: dict[str, str]) -> FullIssue:
        """
        Creates a new project issue.

        See https://docs.gitlab.com/ee/api/issues#new-issue.
        """
        return self.fetch(
            "Issue creating",
            self.url + "/api/v4/projects/" + self.issue_repo_id + "/issues",
            params=params,
            action="post",
        ).json()

    def update_issue(self, issue_iid: int, params: dict[str, str]) -> FullIssue:
        """
        Updates an existing project issue. This request is also used to close or reopen an issue (with state_event).

        At least one of the following parameters is required for the request to be successful:
        assignee_id, assignee_ids, confidential, created_at, description, discussion_locked, due_date, issue_type,
        labels, milestone_id, state_event, title

        See https://docs.gitlab.com/ee/api/issues#edit-an-issue.
        """
        actions: list[str] = list(params.keys())
        for idx, action in enumerate(actions):
            match action:
                case "state_event":
                    actions[idx] = params[action]
                case "remove_labels":
                    actions[idx] = "remove_labels: " + params[action]
                case "add_labels":
                    actions[idx] = "add_labels: " + params[action]
                case _:
                    pass

        return self.fetch(
            "Issue updating (" + ", ".join(actions) + ")",
            self.url + "/api/v4/projects/" + self.issue_repo_id + "/issues/" + str(issue_iid),
            params=params,
            action="put",
        ).json()

    def delete_issue(self, issue_iid: int) -> Response:
        """
        Delete a project issue.

        See https://docs.gitlab.com/ee/api/issues#delete-an-issue.
        """
        return self.fetch(
            "Issue deleting",
            self.url + "/api/v4/projects/" + self.issue_repo_id + "/issues/" + str(issue_iid),
            action="DELETE",
        )

    def search_project(self, name: str) -> list[Project]:
        """
        Get a list of all visible projects across GitLab for the authenticated user matching the search criteria.

        See https://docs.gitlab.com/ee/api/projects.html#list-all-projects.
        """
        return self.fetch_page(
            "Projects pulling",
            self.url + "/api/v4/projects",
            params={"search_namespaces": "true", "search": name, "simple": "true"},
        )

    def get_project_root_dir(self, project_id: int) -> RepositoryTree:
        """
        Get a list of repository files and directories in a project.

        See https://docs.gitlab.com/ee/api/repositories.html#list-repository-tree.
        """
        return self.fetch(
            "Repository tree listing", self.url + "/api/v4/projects/" + str(project_id) + "/repository/tree"
        ).json()

    def get_comments(self, issue_iid: int) -> list[IssueComment]:
        """
        Gets a list of all notes for a single issue.

        See https://docs.gitlab.com/ee/api/notes.html#list-project-issue-notes.
        """
        return self.fetch_page(
            "Comments pulling",
            self.url + "/api/v4/projects/" + self.issue_repo_id + "/issues/" + str(issue_iid) + "/notes",
        )

    def create_comment(self, issue_iid: int, params: dict[str, str]) -> IssueComment:
        """
        Creates a new note to a single project issue.

        See https://docs.gitlab.com/ee/api/notes.html#create-new-issue-note.
        """
        return self.fetch(
            "Comment creating",
            self.url + "/api/v4/projects/" + self.issue_repo_id + "/issues/" + str(issue_iid) + "/notes",
            params=params,
            action="post",
        ).json()

    def delete_comment(self, issue_iid: int, note_id: int) -> Response:
        """
        Deletes an existing note of an issue.

        See https://docs.gitlab.com/ee/api/notes.html#delete-an-issue-note.
        """
        return self.fetch(
            "Comment deleting",
            self.url
            + "/api/v4/projects/"
            + self.issue_repo_id
            + "/issues/"
            + str(issue_iid)
            + "/notes/"
            + str(note_id),
            action="DELETE",
        )
