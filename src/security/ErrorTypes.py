"""Module for custom errors."""


class InternalErrorNoRecovery(RuntimeError):
    """An internal error occurred and there is no state recovery."""

    pass


class GitLabApiFetchError(RuntimeError):
    """An error occurred with requests to the GitLab API."""

    pass


class GitLabApiTypeError(RuntimeError):
    """A type of error occurred with requests to the GitLab API."""

    pass
