#!/usr/bin/env python3
"""RenameAll helpers."""
import logging.config
from pathlib import Path
import re

import yaml

config_file = Path(__file__).parents[0] / "logging.yml"
with config_file.open("r") as stream:
    logging_config = yaml.load(stream, Loader=yaml.FullLoader)
logging.config.dictConfig(logging_config)

from security.ErrorTypes import GitLabApiFetchError
from security.IssueHelper import check_issue_labels_contain

LOGGER_NAME = __name__ if __name__ != "__main__" else "modifyOnce"
log = logging.getLogger(LOGGER_NAME)
log.setLevel(logging.DEBUG)


def add_severity_to_all_component_tickets(severity: str):
    """Add severity to all component tickets."""
    log.info("start add_severity_to_all_component_tickets")

    from security.componentticket import config

    try:
        issues_found = config.api.find_issue(config.COMPONENT_TICKET_PREFIX)
    except GitLabApiFetchError:
        return

    if len(issues_found) == 0:
        log.warning("Abort because there are no issues with title " + config.COMPONENT_TICKET_PREFIX + " found.")
        return

    log.info("Counter: " + str(len(issues_found)))

    for issue in issues_found:
        issue_title = issue["title"]
        log.info("Rename " + issue_title)
        # https://regex101.com/r/I0KNYe/1
        match = re.match(re.escape(config.COMPONENT_TICKET_PREFIX) + r"(\S*)", issue_title)
        if not match:
            log.warning("Skip issue with title: " + issue_title)
            continue
        try:
            _ = match.group(1)
        except KeyError:
            log.warning("Skip issue with title because KeyError in regex group: " + issue_title)
            continue

        new_title = issue_title + " " + severity

        if not check_issue_labels_contain(config.COMPONENT_TICKET_APP_NAME, issue):
            log.warning(
                'Skip because issue labels found do not contain COMPONENT_TICKET_APP_NAME ("'
                + str(issue["labels"])
                + '")'
            )
            continue

        response = config.api.update_issue(issue["iid"], dict({"title": new_title}))
        if not response:
            log.warning("Response was None")
            continue


def add_severity_label_to_all_component_tickets():
    """Add severity to all component tickets."""
    log.info("start add_severity_to_all_component_tickets")

    from security.componentticket import config

    try:
        issues_found = config.api.find_issue(config.COMPONENT_TICKET_PREFIX)
    except GitLabApiFetchError:
        return

    if len(issues_found) == 0:
        log.warning("Abort because there are no issues with title " + config.COMPONENT_TICKET_PREFIX + " found.")
        return

    log.info("Counter: " + str(len(issues_found)))

    for issue in issues_found:
        issue_title = issue["title"]
        log.info("Add label to " + issue_title)
        # https://regex101.com/r/I0KNYe/1
        match = re.match(re.escape(config.COMPONENT_TICKET_PREFIX) + r"(\S*)\s*(\S*)", issue_title)
        if not match:
            log.warning("Skip issue with title: " + issue_title)
            continue
        try:
            _ = match.group(1)
            severity = match.group(2)
        except KeyError:
            log.warning("Skip issue with title because KeyError in regex group: " + issue_title)
            continue

        if not check_issue_labels_contain(config.COMPONENT_TICKET_APP_NAME, issue):
            log.warning(
                'Skip because issue labels found do not contain COMPONENT_TICKET_APP_NAME ("'
                + str(issue["labels"])
                + '")'
            )
            continue
        log.info("Add label: " + str(severity))
        response = config.api.update_issue(issue["iid"], dict({"add_labels": severity}))
        if not response:
            log.warning("Response was None")
            continue


def purge_all_notification():
    """Purge all notification issues."""
    log.info("start purge_all_notification")

    from security.componentticket import config

    title = "[" + config.APP_NAME + "] "
    try:
        issues_found = config.api.find_issue(title)
    except GitLabApiFetchError:
        return

    if len(issues_found) == 0:
        log.error("Abort because there are no issues with title " + title)
        return

    for issue in issues_found:
        log.info("Issue with name " + issue["title"] + " existing")
        if not check_issue_labels_contain(config.APP_NAME, issue):
            log.warning("Skip because in the issue there was no " + config.APP_NAME + " label found")
            continue
        config.api.delete_issue(issue["iid"])


""" # commented out for safety
if __name__ == "__main__":
    # add_severity_to_all_component_tickets("CRITICAL")
    # add_severity_label_to_all_component_tickets()
"""
