"""
@Author: Mr128Bit

This is the main module for JIRAudit.
TODO: Add a description
"""

import sys
import os
import json
import logging
import importlib


import argparse
import urllib3

from cve_utils.cve_utils import *  # pylint: disable=unused-wildcard-import wildcard-import
from score.Manager import *  # pylint: disable=unused-wildcard-import wildcard-import
from jira_api.JiraAPI import JiraAPI  # pylint: disable=unused-wildcard-import
from jira_api.marketplace_api.Plugin import *  # pylint: disable=unused-wildcard-import wildcard-import
from Auditor import Auditor  # pylint: disable=unused-wildcard-import

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(
    prog="JIRAudit - Jira auditing tool",
    description="Scan your jira instance and get feedback on your configuration",
)
parser.add_argument(
    "-p", "--proxy", help="Tunnel requests through a proxy", required=False
)
parser.add_argument(
    "-t",
    "--token",
    help="An admins personal access token for authentication",
    required=False,
)
parser.add_argument(
    "-u", "--username", help="Your username for websudo authentication", required=False
)
parser.add_argument(
    "-pw", "--password", help="Your password for websudo auth", required=False
)
parser.add_argument(
    "-f",
    "--full",
    help="Start a full scan (authenticated)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-fua",
    "--full-unauth",
    help="Start a full scan without authentication (only uses unauth-modules)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-fa",
    "--full-auth",
    help="Start a full scan with authentication (only uses auth-modules)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-d", "--debug", help="Enable debug mode", action="store_true", required=False
)
parser.add_argument(
    "-pe",
    "--plugin-enum",
    help="Start a plugin enumeration (authenticated)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-vc",
    "--version-check",
    help="Check plugin versions on enumeration (use this in combination with -pe)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-epat",
    "--enum-pats",
    help="Enumerate personal access tokens (authenticated)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-cs",
    "--check-supported-platforms",
    help="Check support of required platforms (authenticated)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-upe",
    "--unauth-plugin-enum",
    help="Start a plugin enumeration (unauthenticated)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-uise",
    "--unauth-issue-status-enum",
    help="Start a issue status enumeration (unauthenticated)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-uue",
    "--unauth-user-enum",
    help="Start an unauthenticated user enumeration",
    metavar="<USERLIST>",
    required=False,
)
parser.add_argument(
    "-s",
    "--save",
    help="Save the results as a json file",
    action="store_true",
    required=False,
)
parser.add_argument("-o", "--out", help="Output path for result file", required=False)
# not implemented yet
parser.add_argument(
    "-sm",
    "--silent-mode",
    help="If run in silent mode, only the execution ID and error logs will be printed",
    action="store_true",
    required=False,
)


parser.add_argument("host", help="Hostname of your jira instance", type=str)

args = parser.parse_args()

TEMPLATE = None
BASE_URL = None
DEBUG_MODE = False
PLUGINS_CONFIG = None
SUPPORTED_DATABASES = None
SUPPORTED_JVM = None
AUTHENTICATED = False
USERNAME = None
PASSWORD = None

from settings import *  # pylint: disable=wrong-import-position wildcard-import unused-wildcard-import

FORMAT = "%(asctime)s [JIRAudit] %(message)s"
logging.basicConfig(level=LOG_LEVEL, format=FORMAT)

logging.info("Starting client")

proxy = None

if args.token:
    TOKEN = args.token

if args.password:
    PASSWORD = args.password

if args.host[-1] == "/":
    BASE_URL = args.host[0:-1]
else:
    BASE_URL = args.host

if args.debug:
    DEBUG_MODE = True

if args.proxy:
    proxy = args.proxy
    logging.info("Proxy detected: %s", proxy)

    os.environ["http_proxy"] = proxy
    os.environ["HTTP_PROXY"] = proxy
    os.environ["https_proxy"] = proxy
    os.environ["HTTPS_PROXY"] = proxy


def print_banner():
    """
    Prints the banner :O
    """

    banner = """

____________________________________________________
                                                  
   ___ ___________  ___            _ _ _       
  |_  |_   _| ___ \/ _ \          | (_) |       
    | | | | | |_/ / /_\ \_   _  __| |_| |_      
    | | | | |    /|  _  | | | |/ _` | | __|
/\__/ /_| |_| |\ \| | | | |_| | (_| | | |_        
\____/ \___/\_| \_\_| |_/\__,_|\__,_|_|\__|      

JIRAudit - Version: 1.0 (alpha)   Author: Robin Dost

____________________________________________________
    """

    print(banner)


def load_config():
    """
    Load all configuration files into json object
    """

    global PLUGINS_CONFIG  # pylint: disable=global-statement
    global SUPPORTED_DATABASES  # pylint: disable=global-statement
    global SUPPORTED_JVM  # pylint: disable=global-statement

    try:
        with open(PLUGINS_CONFIG_PATH, "r", encoding="UTF-8") as f:
            jsobj = json.load(f)

            PLUGINS_CONFIG = jsobj
        with open(SUPPORTED_DBS_CONFIG_PATH, "r", encoding="UTF-8") as f:
            jsobj = json.load(f)

            SUPPORTED_DATABASES = jsobj

        with open(SUPPORTED_JVM_CONFIG_PATH, "r", encoding="UTF-8") as f:
            jsobj = json.load(f)

            SUPPORTED_JVM = jsobj

    except Exception as e:  # pylint: disable=broad-exception-caught
        logging.error("Error while loading config: %s", e)
        sys.exit(1)


def get_template():
    """
    Get host template for individual configurations
    """

    templates = [
        f
        for f in os.listdir(TEMPLATES_PATH)
        if os.path.isfile(os.path.join(TEMPLATES_PATH, f)) and f != "__init__.py"
    ]

    i_package = None
    template = None

    for t in templates:
        t = t.replace(".py", "")
        package = f"templates.{t}"
        mod = importlib.import_module(package)
        hosts = getattr(mod, "HOSTS")

        if (not template and "*" in hosts) or BASE_URL in hosts:
            template = t
            i_package = package

    if i_package:
        logging.info("Using template '%s' for execution", template)
        global TEMPLATE  # pylint: disable=global-statement
        TEMPLATE = importlib.import_module(i_package)
    else:
        logging.error("[ERROR] Couldn't find any tempalte für your host")


if __name__ == "__main__":
    load_config()

    JIRA_API = None

    get_template()

    if hasattr(TEMPLATE, "JIRA_USER"):
        USERNAME = TEMPLATE.JIRA_USER
    if hasattr(TEMPLATE, "JIRA_PASSWORD"):
        PASSWORD = TEMPLATE.JIRA_PASSWORD

    if not USERNAME and args.username:
        USERNAME = args.username

    if not PASSWORD and args.password:
        PASSWORD = args.password

    if USERNAME and PASSWORD:
        JIRA_API = JiraAPI(BASE_URL, username=USERNAME, password=PASSWORD)

        JIRA_API.get_session_cookies()
        JIRA_API.authenticate_as_admin()

        authenticated = JIRA_API.init_auth()

        if not authenticated:
            logging.error("Authentication for user %s failed", USERNAME)
            sys.exit(100)
    else:
        JIRA_API = JiraAPI(BASE_URL)

    save_results = False
    path = None
    silent_mode = False

    if args.save:
        save_results = True

    if args.silent_mode and not save_results:
        logging.warning(
            "Do not use silent mode (-sm, --silent) without (-s, --save) option. Ignoring argument"
        )
    elif args.silent_mode and save_results:
        silent_mode = True

    if args.out:
        path = args.out
    elif RESULTS_PATH:
        path = RESULTS_PATH

    auditor = Auditor(
        JIRA_API,
        TEMPLATE,
        SUPPORTED_DATABASES,
        SUPPORTED_JVM,
        PLUGINS_CONFIG,
        results_path=path,
        save_results=save_results,
        silent_mode=silent_mode,
    )

    if not silent_mode:
        print_banner()

    if args.full:
        auditor.full_audit()
    elif args.full_unauth:
        auditor.full_audit_unauth()
    elif args.full_auth:
        auditor.full_audit_auth()
    else:
        if args.unauth_plugin_enum:
            auditor.enum_plugins_unauthenticated()
        if args.plugin_enum:
            if args.version_check:
                auditor.enum_plugins_authenticated(check_versions=True)
            else:
                auditor.enum_plugins_authenticated()
        if args.check_supported_platforms:
            auditor.check_supported_platforms()
        if args.enum_pats:
            auditor.enum_personal_access_tokens()
        if args.unauth_issue_status_enum:
            auditor.enum_issue_status_unauthenticated()
        if args.unauth_user_enum:

            users = []

            if os.path.isfile(args.unauth_user_enum):

                with open(args.unauth_user_enum, "r", encoding="UTF-8") as fl:
                    users = [u.strip() for u in fl.readlines()]

            auditor.enum_users_unauthenticated(users)

    auditor.end_audit()
