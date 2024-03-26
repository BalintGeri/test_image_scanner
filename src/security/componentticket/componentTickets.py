#!/usr/bin/env python3
"""Module for component tickets."""
import contextlib
from itertools import groupby
import json
import logging
import logging.config
import os
from pathlib import Path
import re

import yaml

if __name__ == "__main__":
    config_file = Path(__file__).parents[1] / "logging.yml"
    with config_file.open("r") as stream:
        logging_config = yaml.load(stream, Loader=yaml.FullLoader)
    logging.config.dictConfig(logging_config)

from security.AppSource import app_source_translator, AppSource
from security.componentticket import config
from security.componentticket.CVEOrderHelper import (
    group_by_priority,
    group_by_severity,
    ordered_priority,
    ordered_severity,
)
from security.componentticket.IssueHelper import check_issue_labels_contain, get_instructions_for_labels_removal
from security.CVE import CVE, CVEEncoder
from security.ErrorTypes import GitLabApiFetchError, InternalErrorNoRecovery
from security.GitLabApiTypes import FullIssue, Issue
from security.Ticket import Ticket


LOGGER_NAME = __name__ if __name__ != "__main__" else "componentTickets"
log = logging.getLogger(LOGGER_NAME)
log.setLevel(logging.DEBUG)


def main():
    """Handle notification for component tickets."""
    if config.APP_NAME == app_source_translator[AppSource.SECURITY_CHECKER]:
        visited_projects = main_owasp_reports()
        close_obsolet_issues(visited_projects)
    elif config.APP_NAME == app_source_translator[AppSource.IMAGE_SCANNER]:
        visited_projects = main_trivy_reports()
        close_obsolet_issues(visited_projects)


def main_owasp_reports(dry_run=False) -> list[str]:
    """Save component tickets by owasp reports."""
    dependency_check_report_path_str = os.environ["DEPENDENCY_CHECK_REPORT_PATH"]
    if not dependency_check_report_path_str:
        raise InternalErrorNoRecovery("ENV DEPENDENCY_CHECK_REPORT_PATH was not declared.")
    dependency_check_report_path = Path(dependency_check_report_path_str).resolve(strict=True)

    # Find all owasp reports
    repo_reports = list(dependency_check_report_path.rglob("dependency-check-report.json"))
    workload = len(repo_reports)
    log.info("Start with iterating over " + str(workload) + " repo reports.")
    viewed_projects = []
    for index, repo_report in enumerate(repo_reports):
        project_slug = str(repo_report.resolve().parent.relative_to(dependency_check_report_path))
        log.info("Report " + str(index + 1) + "/" + str(workload) + ": project_slug is " + project_slug)
        # 1. Get all CVEs for repo report
        try:
            cve_list: list[CVE] = get_cve_list_of_repo(repo_report)
        except FileNotFoundError as e:
            log.error(e)
            continue

        # 2. Map all CVEs to corresponding tickets
        for cve in cve_list:
            cve.load_ticket(cached=False)
        # 3. Create component tickets
        save_component_tickets(cve_list, project_slug, dry_run)
        # 4. Save viewed project
        viewed_projects.append(project_slug)
    return viewed_projects


def main_trivy_reports(dry_run=False) -> list[str]:
    """Save component tickets by trivy reports."""
    trivy_report_path_str = os.environ["TRIVY_REPORT_PATH"]
    if not trivy_report_path_str:
        raise InternalErrorNoRecovery("ENV TRIVY_REPORT_PATH was not declared.")
    trivy_report_path = Path(trivy_report_path_str).resolve(strict=True)

    # Find all trivy reports
    image_reports = list(trivy_report_path.rglob("scan_result.json"))
    workload = len(image_reports)
    log.info("Start with iterating over " + str(workload) + " image reports.")
    viewed_projects = []
    for index, image_report in enumerate(image_reports):
        image_slug = str(image_report.resolve().parent.relative_to(trivy_report_path))
        log.info("Report " + str(index + 1) + "/" + str(workload) + ": image_slug is " + image_slug)
        # 1. Get all CVEs for image report
        try:
            cve_list, project_slug = get_cve_list_of_image(image_report)
        except (FileNotFoundError, KeyError, json.decoder.JSONDecodeError) as e:
            log.error(e)
            continue
        # 2. Map all CVEs to corresponding tickets
        for cve in cve_list:
            cve.load_ticket(cached=False)
        # 3. Fix project_slug
        try:
            project_slug = make_project_slug_accurately(project_slug)
        except ImportError as e:
            log.error(e)
            continue
        # 4. Create component tickets
        save_component_tickets(cve_list, project_slug, dry_run)
        # 5. Save viewed project
        viewed_projects.append(project_slug)
    return viewed_projects


def save_component_tickets(cve_list: list[CVE], project_slug: str, dry_run: bool = False):
    """Save tickets grouped by severity with CVEs grouped by priority."""
    log.debug("start with save_component_tickets")
    severity: int
    cve_list_gb_severity: list[CVE]
    for severity, cve_list_gb_severity in [
        (k, list(g)) for k, g in groupby(sorted(cve_list, key=group_by_severity), group_by_severity)
    ]:
        save_component_ticket(cve_list_gb_severity, project_slug, ordered_severity[severity], dry_run)


def close_obsolet_issues(projects_slugs_to_ignore: list[str]):
    """Close obsolet issues for example for deleted repos."""
    log.info("start with close_obsolet_issues")
    try:
        issues_found = config.api.find_issue(config.COMPONENT_TICKET_PREFIX)
    except GitLabApiFetchError:
        return

    if len(issues_found) == 0:
        log.warning("Abort because there are no issues with title " + config.COMPONENT_TICKET_PREFIX + " found.")
        return

    workload = len(issues_found)
    log.info("Start with iterating over " + str(workload) + " issues.")
    for index, issue in enumerate(issues_found):
        issue_title = issue["title"]
        # https://regex101.com/r/I0KNYe/1
        match = re.match(re.escape(config.COMPONENT_TICKET_PREFIX) + r"(\S*)\s*(\S*)", issue_title)
        if not match:
            log.warning("Skip issue with title: " + issue_title)
            continue
        try:
            project_slug = match.group(1)
            severity = match.group(2)
        except KeyError:
            log.warning("Skip issue with title because KeyError in regex group: " + issue_title)
            continue
        if project_slug in projects_slugs_to_ignore:
            log.debug("Ignore project_slug " + project_slug)
            continue
        log.info(
            "Issue "
            + str(index + 1)
            + "/"
            + str(workload)
            + ": project_slug is "
            + project_slug
            + " and severity is "
            + severity
        )
        save_component_ticket([], project_slug, severity=severity, cached_ticket=issue)


def save_component_ticket(
    cve_list: list[CVE],
    project_slug: str,
    severity: str | None = None,
    dry_run: bool = False,
    cached_ticket: Issue | None = None,
) -> Issue | None:
    """Save ticket with CVEs grouped by severity and priority."""
    if not project_slug:
        log.warning("Skip because of missing project_slug.")
        return None
    title = config.COMPONENT_TICKET_PREFIX + project_slug

    if severity:
        title += " " + severity

    if cached_ticket:
        issues_found = [cached_ticket]
    else:
        try:
            issues_found = config.api.find_issue(title)
        except GitLabApiFetchError:
            return None

    saved_ticket: Issue | None = None
    if len(issues_found) > 1:
        # Reduce list to exact matches
        issues_found = [issue for issue in issues_found if title.strip() == str(issue["title"]).strip()]
        log.debug("Reduce issues_found list to " + str(len(issues_found)))
    if len(issues_found) > 1:
        log.warning("Abort because there are too many issues with title " + title + " found.")
        return None
    if len(issues_found) == 1:
        issue = issues_found[0]
        if not check_issue_labels_contain(config.COMPONENT_TICKET_APP_NAME, issue):
            log.warning(
                "Abort because issue labels found for title "
                + title
                + ' do not contain COMPONENT_TICKET_APP_NAME ("'
                + str(issue["labels"])
                + '")'
            )
            return None
        if title != issue["title"]:
            log.warning("Title does not match completely. Searched: " + title + ", found: " + issue["title"])
        log.info("Issue with title " + title + " found, go to update_ticket().")
        if not dry_run:
            output = update_ticket(issue=issue, cve_list=cve_list, severity=severity)
            if output:
                saved_ticket, cve_list = output
    elif len(cve_list) > 0:
        log.info("No issue with title " + title + " found, go to create_ticket().")
        if not dry_run:
            saved_ticket = create_ticket(cve_list, title, additional_labels=severity)
    else:
        log.info("No issue with title " + title + " found and no CVEs. Skip.")

    if saved_ticket is None:
        return None

    created_link_counter = 0
    for cve in cve_list:
        cve_ticket: Ticket | None = cve.ticket
        if cve_ticket:
            with contextlib.suppress(GitLabApiFetchError):
                config.api.create_link_between_issues(
                    saved_ticket["iid"], cve_ticket.iid, log_level_success=logging.DEBUG, log_level_fail=logging.INFO
                )
                created_link_counter += 1

    if created_link_counter:
        log.info("Issue link creating done (" + str(created_link_counter) + ").")

    saved_ticket = auto_close_ticket(saved_ticket, cve_list)
    return saved_ticket


def create_ticket(cve_list: list[CVE], title: str, additional_labels="") -> FullIssue | None:
    """Create ticket."""
    if len(cve_list) == 0:
        raise InternalErrorNoRecovery("Tried to create a ticket with zero CVEs.")
    description = get_ticket_description_text(cve_list)
    try:
        return config.api.create_issue(
            {
                "title": title,
                "assignee_ids": config.GITLAB_ISSUE_ASSIGNEES,
                "labels": config.COMPONENT_TICKET_ADD_LABELS + ("," + additional_labels if additional_labels else ""),
                "description": description,
            }
        )
    except GitLabApiFetchError:
        return None


def update_ticket(issue: Issue, cve_list: list[CVE], severity=None) -> tuple[Issue, list[CVE]] | None:
    """Update ticket."""
    parsed_old_cve_list = parse_cve_list_from_description(issue["description"])
    # Filter wrong severity items, just for migration 12.01.2024
    parsed_old_cve_list = [cve for cve in parsed_old_cve_list if severity is None or cve.severity == severity]
    merged_cve_list = merge_cve_list(parsed_old_cve_list, cve_list)
    for cve in merged_cve_list:
        cve.load_ticket(cached=True)
    update_config = {}

    if issue["state"] == "closed":
        if ticket_should_be_closed(cve_list):
            log.info("Updating not necessary, ticket should stay closed. Reason: All CVEs closed. Skip.")
            return None

        if check_issue_labels_contain(config.FORCE_CLOSE_LABEL, issue):
            log.info("Updating not necessary, ticket should stay closed. Reason: FORCE_CLOSE_LABEL detected. Skip.")
            return None

        if ticket_has_any_new_cve(merged_cve_list, parsed_old_cve_list):
            log.debug(
                "new: "
                + str(set([i for i in merged_cve_list if i.is_ticket_open_or_none()]))
                + ", old: "
                + str(set(parsed_old_cve_list))
            )
            # New CVE found.
            update_config = {"state_event": "reopen"}
        else:
            # suppress unnecessary reopening
            log.info(
                "Reopening not necessary, ticket should stay closed. Reason: No new open CVE. Continue with update."
            )

    description = get_ticket_description_text(merged_cve_list)

    if description == issue["description"]:
        log.info(
            "Updating"
            + (" (+" + "+".join(update_config.values()) + ")" if update_config else "")
            + " not necessary, nothing changed. Skip."
        )
        return None

    if ticket_has_any_new_cve(merged_cve_list, parsed_old_cve_list):
        update_config = dict(update_config, **get_instructions_for_labels_removal(issue))

    try:
        response = config.api.update_issue(issue["iid"], dict({"description": description}, **update_config))
    except GitLabApiFetchError:
        return None
    return response, merged_cve_list


def get_ticket_description_text(cve_list: list[CVE]) -> str:
    """
    Return ticket description with CVEs grouped by severity and priority.

    If you change the ticket description generator, then all closed tickets will be reopened without a reason (!).
    """
    ticket_desc = ""

    def group_by_apps(cl: list[CVE]) -> list[list[CVE]]:
        grouped_lists: list[list[CVE]] = []
        for c in cl:
            success = False
            for grouped_list in grouped_lists:
                if c in grouped_list:
                    grouped_list.append(c)
                    success = True
                    break
            if not success:
                grouped_lists.append([c])
        return grouped_lists

    severity: int
    cve_list_gb_severity: list[CVE]
    for severity, cve_list_gb_severity in [
        (k, list(g)) for k, g in groupby(sorted(cve_list, key=group_by_severity), group_by_severity)
    ]:
        ticket_desc += f"\n## {ordered_severity[severity]}"
        priority: int
        cve_list_gb_priority: list[CVE]
        for priority, cve_list_gb_priority in [
            (k, list(g)) for k, g in groupby(sorted(cve_list_gb_severity, key=group_by_priority), group_by_priority)
        ]:
            ticket_desc += f'\n### {"Prio " + str(priority) if priority != ordered_priority[None] else "No priority"}'
            for associated_cve_list in group_by_apps(cve_list_gb_priority):
                smart_strings = []
                for cve in associated_cve_list:
                    t = cve.ticket
                    if t:
                        smart_strings.append(
                            add_img_suffix_if(
                                strikethrough_if("#" + str(t.iid) + "+s", t.is_closed),
                                "Forced to close",
                                t.forced_closed,
                            )
                        )
                    else:
                        smart_strings.append(str(cve.name) + " (ticket not found)")
                ticket_desc += f'\n- {", ".join(smart_strings)}'

    if ticket_desc == "":
        ticket_desc = "\\<Your lucky. No affected CVEs.\\>"

    # add hidden json data for parsing
    ticket_desc += (
        "\n\nPlease do not edit this ticket body, as it is generated automatically. "
        "Please write comments instead.\n"
        "\n<!--beginn-components-init " + str(json.dumps(cve_list, cls=CVEEncoder)) + " end-components-init-->"
    )

    return ticket_desc


def strikethrough_if(msg: str, condition: bool | None) -> str:
    """Strikethrough the message if condition is met."""
    return "~~" + str(msg) + "~~" if condition else str(msg)


def add_img_suffix_if(msg: str, img_text: str, condition: bool | None) -> str:
    """Add text (rendered as image) as suffix to message if condition is met."""
    img_text = img_text.replace("-", "_")
    img_src = "https://img.shields.io/badge/-" + img_text + "-important.svg"
    return str(msg) + ' <img src="' + img_src + '">' if condition else str(msg)


def parse_cve_list_from_description(description: str) -> list[CVE]:
    """Parse CVE list from description."""
    match = re.search("<!--beginn-components-init (.*) end-components-init-->", description)
    cve_list = []
    if match:
        try:
            for cve in json.loads(str(match.group(1)).strip()):
                try:
                    cve_list.append(CVE(**cve))
                except TypeError:
                    log.warning("Got unexpected CVE element: " + str(cve) + ". Will wipe out this element.")
        except json.decoder.JSONDecodeError:
            log.warning('In ticket description was no valid JSON document. Found: "' + str(match.group(1)) + '"')
    else:
        log.warning('In ticket description was no regex match found. Description: "' + str(description) + '"')
    return cve_list


def merge_cve_list(*cve_lists: list[CVE]) -> list[CVE]:
    """Append unique items from lists without losing order."""
    merged_cve_list = []
    for cve_list in cve_lists:
        for cve in cve_list:
            try:
                # if found (see __eq__) -> replace
                i = merged_cve_list.index(cve)
                merged_cve_list[i] = cve
            except ValueError:
                # else append
                merged_cve_list.append(cve)
    return merged_cve_list


def auto_close_ticket(ticket: Issue, cve_list: list[CVE]) -> Issue:
    """Close ticket and remove labels if ticket_should_be_closed is true."""
    if ticket_should_be_closed(cve_list):
        update_config = dict({"state_event": "close"}, **get_instructions_for_labels_removal(ticket))
        with contextlib.suppress(GitLabApiFetchError):
            return config.api.update_issue(ticket["iid"], update_config)
    return ticket


def ticket_should_be_closed(cve_list: list[CVE]) -> bool:
    """Return true if no CVE in list or all CVEs closed."""
    return len(cve_list) == 0 or all(not cve.is_ticket_open_or_none() for cve in cve_list)


def ticket_has_any_new_cve(new_cve_list: list[CVE], old_cve_list: list[CVE]) -> bool:
    """Return true if new CVE found by comparison."""
    return bool(set([i for i in new_cve_list if i.is_ticket_open_or_none()]) - set(old_cve_list))


def get_cve_list_of_repo(json_report_file: Path) -> list[CVE]:
    """
    Parse json for CVEs.

    :param json_report_file: Owasp dependency-scanner report file
    :return: List of CVEs (filled with name and severity)
    """
    if not json_report_file.exists():
        raise FileNotFoundError(
            "File is missing. We can skip this file, but this is really unexpected. " "File: " + str(json_report_file)
        )

    with json_report_file.open("r") as f:
        data = json.load(f)

    # Iterate through all filtered vulnerabilities
    cve_list = []
    for dependency in data["dependencies"]:
        if "vulnerabilities" in dependency:
            for vulnerability in dependency["vulnerabilities"]:
                if is_severity_to_be_obtained(vulnerability["severity"]):
                    name = vulnerability["name"]
                    severity = vulnerability["severity"]
                    cve_list.append(CVE(name, severity, source=AppSource.SECURITY_CHECKER.value))
                else:
                    if vulnerability["severity"] in ("high", "critical"):
                        print(vulnerability)
    return list(set(cve_list))


def get_cve_list_of_image(json_report_file: Path) -> tuple[list[CVE], str]:
    """
    Parse json for CVEs.

    :param json_report_file: Trivy report file
    :return: List of CVEs (filled with name and severity)
    """
    if not json_report_file.exists():
        raise FileNotFoundError(
            "File is missing. We can skip this file, but this is really unexpected. " "File: " + str(json_report_file)
        )

    with json_report_file.open("r") as f:
        data = json.load(f)

    try:
        namespace = data["Metadata"]["ImageConfig"]["config"]["Labels"]["ci.project.namespace"]
        name = data["Metadata"]["ImageConfig"]["config"]["Labels"]["ci.project.name"]
    except KeyError:
        raise KeyError("Mapping to GitLab Repo missing, skip report " + str(json_report_file))
    repo_slug = namespace + "/" + name
    log.info("From labels repo_slug found: " + repo_slug)
    # Iterate through all filtered vulnerabilities
    cve_list = []
    for dependency in data["Results"]:
        if "Vulnerabilities" in dependency:
            for vulnerability in dependency["Vulnerabilities"]:
                if is_severity_to_be_obtained(vulnerability["Severity"]):
                    name = vulnerability["VulnerabilityID"]
                    severity = vulnerability["Severity"]
                    cve_list.append(CVE(name, severity, source=AppSource.IMAGE_SCANNER.value))
    return list(set(cve_list)), repo_slug


def is_severity_to_be_obtained(severity: str) -> bool:
    """Return true if severity is set to be obtained."""
    # return severity.lower() in ("high", "critical")  # TODO Comment out until 2024
    return severity in ("HIGH", "CRITICAL")


def make_project_slug_accurately(project_slug: str) -> str:
    """If project_slug pins to SCS repo, add /backend."""
    try:
        projects_found = config.api.search_project(project_slug)
    except GitLabApiFetchError:
        raise ImportError('Project for slug "' + project_slug + '" not found. Fetch failed.')

    if len(projects_found) == 0:
        raise ImportError("Abort because there are zero projects with name " + project_slug + " found.")
    project_id: int | None = None
    for project in projects_found:
        if project["path_with_namespace"] == project_slug:
            project_id = project["id"]

    if project_id is None:
        raise ImportError(
            'Abort because project paths found do not match project_slug ("'
            + str([project["path_with_namespace"] for project in projects_found])
            + '")'
        )

    try:
        root_dir = config.api.get_project_root_dir(project_id)
    except GitLabApiFetchError:
        raise ImportError("Project root dir fetch failed.")

    significant_dirs = [o["name"] for o in root_dir if o["name"] in ["backend", "frontend"] and o["type"] == "tree"]
    if any(significant_dirs):
        log.info('Found a significant directory in repo "' + project_slug + '". Dirs: ' + str(significant_dirs))
        return project_slug + "/backend"
    return project_slug


if __name__ == "__main__":
    main()
