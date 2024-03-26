#!/usr/bin/env python3
"""Module for CVE tickets."""
import json
import logging.config
from pathlib import Path
import re
import subprocess
import tempfile

import yaml

from security.cveticket.config import DESIGNATED_TEAM

if __name__ == "__main__":
    config_file = Path(__file__).parents[1] / "logging.yml"
    with config_file.open("r") as stream:
        logging_config = yaml.load(stream, Loader=yaml.FullLoader)
    logging.config.dictConfig(logging_config)

from security.cveticket import config
from security.cveticket.Component import ComponentFactory
from security.cveticket.CVE import CVE
from security.ErrorTypes import GitLabApiFetchError
from security.GitLabApiTypes import Issue
from security.IssueHelper import check_issue_labels_contain

LOGGER_NAME = __name__ if __name__ != "__main__" else "cveTickets"
log = logging.getLogger(LOGGER_NAME)
log.setLevel(logging.DEBUG)


def main():
    """Handle notification for CVE tickets."""
    visited_projects = send_notification()
    close_obsolet_issues(visited_projects)


def send_notification() -> list[str]:
    """Save CVE tickets by CVE reports."""
    log.info("start with send_notification")

    dependency_check_report_path = Path(config.CVE_PATH).resolve(strict=True)

    # Find all cve reports
    cve_reports = list(dependency_check_report_path.rglob("*.json"))
    workload = len(cve_reports)
    viewed_projects = []

    for index, json_report_file in enumerate(cve_reports):
        log.info("Report " + str(index + 1) + "/" + str(workload) + ": cve is " + json_report_file.stem)

        # 1. Get all data for report
        try:
            cve: CVE = get_cve_of_report(json_report_file)
        except FileNotFoundError as e:
            log.error(e)
            continue

        viewed_projects.append(cve.name)

        save_cve_ticket(cve)
    return viewed_projects


def get_cve_of_report(json_report_file: Path) -> CVE:
    """
    Parse json for components.

    :param json_report_file: report file
    :return: List of components
    """
    if not json_report_file.exists():
        raise FileNotFoundError(
            "File is missing. We can skip this file, but this is really unexpected. " "File: " + str(json_report_file)
        )

    with json_report_file.open("r") as f:
        data = json.load(f)

    component_list = []
    # Iterate through all components
    for component in data["components"]:
        c = ComponentFactory()
        c.name = component["name"]
        c.full_path = component["fullPath"]
        c.src = component["src"]
        c.version = component["version"]
        c.url_report = component["urlReport"]
        c.sonar_direct_link = component.get("sonar_direct_link", "")
        c.suggestion = component.get("suggestion", "")

        if not config.SONAR_TOKEN:
            c.sonar_direct_link = ""
        elif not c.sonar_direct_link:
            c.sonar_direct_link = "\\\nsonarqube: report upload failed"
        else:
            c.sonar_direct_link = "\\\nsonarqube: [dependency check report](" + c.sonar_direct_link + ")"

        if c.suggestion:
            c.suggestion = "\\\n" + c.suggestion

        built_component = c.build()
        if built_component in component_list:
            log.warning("Duplicated component found. Skip it.")
            continue
        component_list.append(built_component)

    return CVE(
        data["name"], data["severity"], data["description"], data["url"], data.get("labels"), list(component_list)
    )


def save_cve_ticket(
    cve: CVE,
    dry_run: bool = False,
    cached_ticket: Issue | None = None,
) -> None:
    """Save ticket with the CVE."""
    url_run = config.CI_JOB_URL
    affected_components = ""
    affected_components_hidden = []

    for c in cve.components:
        affected_components += (
            "\n- [ ] <details><summary><code>" + c.full_path + ":" + c.version + "</code></summary><!--end-summary-->\n"
            "Name: " + c.name + " " + c.suggestion + "\\\n"
            "" + c.src + " \\\n"
            "Report: [Link to "
            + config.APP_NAME
            + " job artifact]("
            + c.url_report
            + ") "
            + c.sonar_direct_link
            + " </details>"
        )
        affected_components_hidden.append({"full_path": c.full_path, "name": c.name, "src": c.src})

    # ordering affected components so a diff in the later procedure is safe
    affected_components_hidden.sort(key=lambda v: [v[k] for k in sorted(v.keys(), reverse=True)])

    title = "[" + config.APP_NAME + "] " + cve.name

    if cached_ticket:
        issues_found = [cached_ticket]
    else:
        try:
            issues_found = config.api.find_issue(title)
        except GitLabApiFetchError:
            return

    if len(issues_found) > 1:
        log.warning("Abort because there are too many issues with title " + title)
        return

    if len(issues_found) == 1:
        # Issue found
        issue = issues_found[0]
        issue_iid = issue["iid"]
        old_title = issue["title"]
        log.info("Issue already existing. Name: " + old_title)

        if not check_issue_labels_contain(config.APP_NAME, issue):
            log.warning("Abort because in the issue there was no " + config.APP_NAME + " label found")
            return

        if check_issue_labels_contain(config.FORCE_CLOSE_LABEL, issue):
            log.warning("Abort because in the issue there was a " + config.FORCE_CLOSE_LABEL + " label found")
            return

        try:
            comments_found = config.api.get_comments(issue_iid)
        except GitLabApiFetchError:
            return

        comments_found = [c for c in comments_found if c["body"].startswith(config.SEARCH_COMMENT_START)]

        if len(comments_found) > 1:
            log.warning('Abort because there are too many comments starting with "' + config.SEARCH_COMMENT_START + '"')
            return
        if len(comments_found) == 0:
            log.warning('Abort because there was no comment starting with "' + config.SEARCH_COMMENT_START + '"')
            return
        comment = comments_found[0]
        note_id = comment["id"]
        state = issue["state"]
        if state == "opened":
            remove_scheduled_reopening_label_if_found(issue, "Issue is already open")
            add_designated_team_label_if_not_found(issue, "T1 label was not found")

        old_comment_body = comment["body"]

        init_affected_components_hidden = use_regex(
            "<!--beginn-components-init (.+) end-components-init-->",
            1,
            old_comment_body,
            "ticket comment",
            "hidden init_affected_components",
        )

        # Use json for pretty printing changelog
        changelog = diff_issue_latest(
            json.dumps(init_affected_components_hidden, indent=2),
            json.dumps(affected_components_hidden, indent=2),
        )

        if not changelog:
            log.debug("no changes")
            changelog = (
                "[Note: There is no changelog because since this run the affected components match "
                "the ticket text from above again.]"
            )
        else:
            log.debug("Save changelog")

        old_affected_components_hidden = use_regex(
            "<!--beginn-components (.+) end-components-->",
            1,
            old_comment_body,
            "ticket comment",
            "hidden affected_components",
        )

        changelog2 = diff_issue_latest(str(old_affected_components_hidden), str(affected_components_hidden))
        if not changelog2:
            log.debug("no difference: components not changed in compare with comment data")
            remove_scheduled_reopening_label_if_found(issue, "No change detected anymore. Prevented wrong reopening?")
            return

        log.debug(changelog2)
        log.info("differences! Components changed in compare with comment data (See diff in LOG_FILE)")

        if state == "closed":
            # Reopen mechanism

            result = add_scheduled_reopening_label_if_not_found(issue, "")  # only scheduled
            if result:
                return
            try:
                # was already scheduled, now executing reopen
                config.api.update_issue(
                    issue_iid, {"state_event": "reopen", "remove_labels": config.SCHEDULED_REOPENING_LABEL_NAME}
                )
            except GitLabApiFetchError:
                return
        try:
            config.api.delete_comment(issue_iid, note_id)
        except GitLabApiFetchError:
            return

        body = (
            config.SEARCH_COMMENT_START + "(" + url_run + "): Update \\\n"
            "**Severity**: " + cve.severity + " \\\n"
            "**Diff**:\n"
            "```diff\n"
            "" + changelog + "\n"
            "```\n"
            "**Affected components (default branch)**:\n"
            "" + affected_components.replace("- [ ] ", "").replace("<!--end-summary-->", "\n") + "\n"
            "<!--beginn-components-init "
            + list_to_json_str(init_affected_components_hidden)
            + " end-components-init-->\n"
            "<!--beginn-components " + list_to_json_str(affected_components_hidden) + " end-components-->"
        )
    else:
        # No issue found, so create one

        cve_description = cve.description
        if "\n\n" in cve_description or "# " in cve_description:
            # Pack in Markdown code block
            cve_description = "\n`````\n" + cve_description + "\n`````"
        else:
            # Pack in Markdown inline-code
            cve_description = "`````" + cve_description + "````` \\"

        issue_description = (
            "CVE: [" + cve.name + "](" + cve.url + ")\n"
            "**Severity**: " + cve.severity + " \\\n"
            "**Pipeline**: [Link to " + config.APP_NAME + " job run](" + url_run + ")\n"
            "\n"
            "**Description from [source](" + cve.url + ")**: " + cve_description + "\n"
            "\\\n"
            "**Affected components (default branch)**:\n"
            "" + affected_components + "\n"
            "<br />\n"
            "If you want to have this ticket regenerated, just delete it and it will reappear tomorrow.\n"
            "If you want to suppress the ticket, close it. It will be reopened automatically "
            "if something changes in the affected-components.\n"
            "<br />\n"
            "<!--Automatically created by " + config.APP_NAME + "-->"
        )

        try:
            response = config.api.create_issue(
                {
                    "title": title,
                    "assignee_ids": config.GITLAB_ISSUE_ASSIGNEES,
                    "labels": ",".join([config.APP_NAME, "CVE", DESIGNATED_TEAM, "severity:" + cve.severity, cve.labels]),
                    "description": issue_description,
                }
            )
        except GitLabApiFetchError:
            return

        issue_iid = response["iid"]
        body = (
            "" + config.SEARCH_COMMENT_START + "(" + url_run + ") - Please ignore this comment.\n"
            "<!--beginn-components-init " + list_to_json_str(affected_components_hidden) + " end-components-init-->\n"
            "<!--beginn-components " + list_to_json_str(affected_components_hidden) + " end-components-->"
        )

    try:
        config.api.create_comment(issue_iid, {"body": body})
    except GitLabApiFetchError:
        return


def diff_issue_latest(old: str, new: str) -> str | None:
    """Get diff string of old and new or None if no differences found."""
    temp_old = tempfile.NamedTemporaryFile(mode="w", delete=False)
    temp_new = tempfile.NamedTemporaryFile(mode="w", delete=False)
    temp_old.write(old + "\n")
    temp_new.write(new + "\n")

    temp_old.close()
    temp_new.close()

    result = subprocess.run(
        ["diff", "-bB", "-U", "0", "--label", "issue text", "--label", "latest", temp_old.name, temp_new.name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )

    Path(temp_old.name).unlink()
    Path(temp_new.name).unlink()

    if result.returncode == 0:
        return None
    return str(result.stdout)


def close_obsolet_issues(cve_to_ignore: list[str]):
    """Close obsolet issues for example for deleted repos."""
    log.info("start with close_obsolet_issues")

    title = "[" + config.APP_NAME + "] "

    try:
        issues_found = config.api.find_issue(title)
    except GitLabApiFetchError:
        return

    if len(issues_found) == 0:
        log.warning("Abort because there are no issues with title " + title + " found.")
        return

    workload = len(issues_found)
    log.info("Start with iterating over " + str(workload) + " issues.")
    for index, issue in enumerate(issues_found):
        issue_title = issue["title"]
        # https://regex101.com/r/I0KNYe/1
        match = re.match(re.escape(title) + r"(\S+)", issue_title)
        if not match:
            log.warning("Skip issue with title: " + issue_title)
            continue
        try:
            name = match.group(1)
        except KeyError:
            log.warning("Skip issue with title because KeyError in regex group: " + issue_title)
            continue

        if not check_issue_labels_contain(config.APP_NAME, issue):
            log.warning("Skip because in the issue there was no " + config.APP_NAME + " label found")
            continue

        if name in cve_to_ignore:
            continue
        log.debug("Issue " + str(index + 1) + "/" + str(workload) + ": name is " + name)

        if issue["state"] == "opened":
            log.info("Issue with name " + issue_title + " is obsolet")
            close_obsolet_issue(issue)
        elif issue["state"] == "closed":
            remove_scheduled_reopening_label_if_found(
                issue,
                "Issue with name "
                + issue_title
                + " should stay closed because it is obsolet. Prevented wrong reopening?",
            )


def add_scheduled_reopening_label_if_not_found(issue: Issue, reason: str) -> bool:
    """If issue has no SCHEDULED_REOPENING_LABEL_NAME label and no FORCE_REOPEN flag is set add the label."""
    if not check_issue_labels_contain(config.SCHEDULED_REOPENING_LABEL_NAME, issue) and not config.FORCE_REOPEN:
        log.info("Reason for label adding: " + reason)
        try:
            config.api.update_issue(issue["iid"], {"add_labels": config.SCHEDULED_REOPENING_LABEL_NAME})
            return True
        except GitLabApiFetchError:
            pass
    return False


def remove_scheduled_reopening_label_if_found(issue: Issue, reason: str) -> bool:
    """If issue has SCHEDULED_REOPENING_LABEL_NAME label remove the label."""
    if check_issue_labels_contain(config.SCHEDULED_REOPENING_LABEL_NAME, issue):
        log.info("Reason for label removing: " + reason)
        try:
            config.api.update_issue(issue["iid"], {"remove_labels": config.SCHEDULED_REOPENING_LABEL_NAME})
            return True
        except GitLabApiFetchError:
            pass
    return False

def add_designated_team_label_if_not_found(issue: Issue, reason: str) -> bool:
    """If issue does not have team label, add the label."""
    if not check_issue_labels_contain(config.DESIGNATED_TEAM, issue):
        log.info("Reason for label adding: " + reason)
        try:
            config.api.update_issue(issue["iid"], {"add_labels": config.DESIGNATED_TEAM})
            return True
        except GitLabApiFetchError:
            pass
    return False

def close_obsolet_issue(issue: Issue) -> None:
    """Close obsolet issues for example for deleted repos."""
    issue_iid = issue["iid"]
    url_run = config.CI_JOB_URL

    try:
        comments_found = config.api.get_comments(issue_iid)
    except GitLabApiFetchError:
        return

    comments_found = [c for c in comments_found if c["body"].startswith(config.SEARCH_COMMENT_START)]

    if len(comments_found) > 1:
        log.warning('Abort because there are too many comments starting with "' + config.SEARCH_COMMENT_START + '"')
        return
    if len(comments_found) == 0:
        log.warning('Abort because there was no comment starting with "' + config.SEARCH_COMMENT_START + '"')
        return
    comment = comments_found[0]
    note_id = comment["id"]

    old_comment_body = comment["body"]
    init_affected_components_hidden = use_regex(
        "<!--beginn-components-init (.+) end-components-init-->",
        1,
        old_comment_body,
        "ticket comment",
        "hidden init_affected_components",
    )
    try:
        config.api.delete_comment(issue_iid, note_id)
    except GitLabApiFetchError:
        return

    body = (
        "" + config.SEARCH_COMMENT_START + "(" + url_run + "): Automatic closure due to obsolescence.\n"
        "<!--beginn-components-init " + list_to_json_str(init_affected_components_hidden) + " end-components-init-->\n"
        "<!--beginn-components [] end-components-->"
    )

    try:
        log.debug("Close-Comment creating")
        config.api.create_comment(issue_iid, {"body": body})
        config.api.update_issue(issue_iid, {"state_event": "close"})
    except GitLabApiFetchError:
        return


def use_regex(pattern: str, group_ix: int, data: str, desc_data: str, desc_search: str):
    """
    Retrieve json list in data string using regex.

    :param pattern: Pattern to search in data
    :param group_ix: Select group_id in pattern
    :param data: Data to search in
    :param desc_data: Description for the data
    :param desc_search: Description for the search
    :return: Json list or empty list if no match or regex invalid
    """
    match = re.search(pattern, data)
    if not match:
        log.warning("In " + desc_data + ' was no regex match found. Data: "' + str(data) + '"')
        return []
    try:
        return json.loads(str(match.group(group_ix)).strip())
    except json.decoder.JSONDecodeError:
        log.warning(
            "In "
            + desc_data
            + " the "
            + desc_search
            + ' was no valid JSON document. Found: "'
            + str(match.group(group_ix))
            + '"'
        )
        return []


def list_to_json_str(list_to_json: list):
    """Convert list object to json string."""
    return json.dumps(list_to_json)


if __name__ == "__main__":
    main()
