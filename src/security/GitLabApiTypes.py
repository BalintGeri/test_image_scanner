"""Module for custom GitLab API responses."""
from typing import TypedDict


class Issue(TypedDict):
    """Issue, see https://docs.gitlab.com/ee/api/issues."""

    # flake8: noqa: A003
    id: int
    iid: int
    project_id: int
    title: str
    description: str
    state: str
    created_at: str
    updated_at: str
    closed_at: str | None
    closed_by: dict | None
    labels: list
    milestone: dict | None
    assignees: list
    author: dict
    # flake8: noqa: A003
    type: str
    assignee: list
    user_notes_count: int
    merge_requests_count: int
    upvotes: int
    downvotes: int
    due_date: str | None
    confidential: bool
    discussion_locked: bool | None
    issue_type: str
    web_url: str
    time_stats: dict
    task_completion_status: dict


class FindIssue(Issue):
    """Issue, see https://docs.gitlab.com/ee/api/issues."""

    has_tasks: bool
    references: dict
    severity: str
    service_desk_reply_to: str | None
    _links: dict
    moved_to_id: None
    task_status: str


class FullIssue(FindIssue):
    """Issue, see https://docs.gitlab.com/ee/api/issues."""

    subscribed: bool


class IssueLink(TypedDict):
    """Link (Issue), see https://docs.gitlab.com/ee/api/issue_links.html."""

    source_issue: Issue
    target_issue: Issue
    link_type: str


class Namespace(TypedDict):
    """Namespace, see https://docs.gitlab.com/ee/api/namespaces.html."""

    # flake8: noqa: A003
    id: int
    name: str
    path: str
    kind: str
    full_path: str
    parent_id: None
    avatar_url: None
    web_url: str


class Project(TypedDict):
    """Project, see https://docs.gitlab.com/ee/api/projects.html."""

    # flake8: noqa: A003
    id: int
    description: str
    name: str
    name_with_namespace: str
    path: str
    path_with_namespace: str
    created_at: str
    default_branch: str
    tag_list: list
    topics: list
    ssh_url_to_repo: str
    http_url_to_repo: str
    web_url: str
    readme_url: str
    forks_count: int
    avatar_url: str
    star_count: int
    last_activity_at: str
    namespace: Namespace


class RepositoryTree(TypedDict):
    """Repository tree, see https://docs.gitlab.com/ee/api/repositories.html#list-repository-tree."""

    # flake8: noqa: A003
    id: str
    name: str
    # flake8: noqa: A003
    type: str
    path: str
    mode: str


class IssueComment(TypedDict):
    """Comment in issue, see https://docs.gitlab.com/ee/api/notes.html#list-project-issue-notes."""

    # flake8: noqa: A003
    id: int
    body: str
    attachment: None
    author: dict
    created_at: str
    updated_at: str
    system: bool
    noteable_id: int
    noteable_type: str
    project_id: int
    resolvable: bool
    confidential: bool
    internal: bool
    noteable_iid: int
