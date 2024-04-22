"""
Util module for requesting cve information for jira

Author:     @Mr128Bit
Created:    04/24
"""

import requests


def get_cves(jira_sw_version: str, jira_sd_version: str = None) -> list:
    """
    Get cves from different sources and return a unique list

    Parameters
    ----------
        jira_sw_version : str
            Jira software version

        jira_sd_version : str (optional)
            Jira service desk version

    Returns
    -------
        cve_list : list
            A list of unique cves
    """

    cves = get_cves_by_version(jira_sw_version)
    cves += get_jira_cves(jira_sw_version, is_jira_sd=False)

    if jira_sd_version:
        cves += get_jira_cves(jira_sw_version, is_jira_sd=True)

    cve_ids = []
    cve_list = []

    for cve in cves:

        cid = cve.get("cve_id")

        if cid not in cve_ids:
            cve_ids.append(cid)
            cve_list.append(cve)

    return cve_list


def get_cves_by_version(version: str) -> list:
    """
    Get all public security vulnerabilities for Jira via https://services.nvd.nist.gov

    Parameters
    ----------
        version : str
            Jira software version

    Returns
    -------
        cves : list
            A list of found cves
    """

    resp = requests.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=cpe:2.3:a:atlassian:jira_data_center:{version}:*:*:*:*:*:*:*",
        timeout=10,
    )

    cves = []

    if resp.status_code == 200:
        jsobj = resp.json()

        vulnerabilities = jsobj.get("vulnerabilities")

        for vuln in vulnerabilities:
            baseSeverity = None
            metrics = vuln["cve"]["metrics"]

            if metrics.get("cvssMetricV31"):
                baseSeverity = metrics["cvssMetricV31"][0]["cvssData"]["baseSeverity"]
            elif metrics.get("cvssMetricV2"):
                baseSeverity = metrics["cvssMetricV2"][0]["baseSeverity"]

            cve = vuln["cve"]["id"]
            url = f"https://nvd.nist.gov/vuln/detail/{cve}"

            cves.append({"cve_id": cve, "severity": baseSeverity, "reference": url})

    return cves


def get_jira_cves(version, is_jira_sd=False) -> list:  # pylint: disable=too-many-locals
    """
    Get all public security vulnerabilities for Jira software and service desk via https://jira.atlassian.com

    Parameters
    ----------
        is_jira_sd : bool
            Set this flag to true when the version is a jira service desk version

    Returns
    -------
        cves : list
            A list of found cves
    """

    project = "JSWSERVER"
    filter_id = "98706"

    if is_jira_sd:
        project = "JSDSERVER"
        filter_id = "98707"

    cves = []
    payload = {
        "startIndex": "0",
        "filterId": filter_id,
        "jql": f'project = {project} AND type = "Public Security Vulnerability"  and affectedVersion ~ "{version}"',
        "layoutKey": "split-view",
    }
    header = {
        "Content-Type": "application/x-www-form-urlencoded",
        "X-Atlassian-Token": "no-check",
    }

    # TODO: Add paging, but it is currently not needed; laaater
    # TODO: Better exception handling
    jsobj = None

    try:
        response = requests.post(
            "https://jira.atlassian.com/rest/issueNav/1/issueTable",
            data=payload,
            headers=header,
            timeout=10,
        )
        jsobj = response.json()
    except Exception as e:
        raise e

    issue_table = jsobj.get("issueTable")
    issues = issue_table.get("issueKeys")

    for issue in issues:
        response = None

        try:
            response = requests.get(
                f"https://jira.atlassian.com/rest/api/2/issue/{issue}", timeout=10
            )
        except Exception as e:
            raise e

        response = response.json()

        fields = response.get("fields")

        cve_id = fields.get("customfield_20631")
        severity = fields.get("customfield_20630").get("value").upper()

        cves.append(
            {
                "cve_id": cve_id,
                "severity": severity,
                "reference": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        )

    return cves
