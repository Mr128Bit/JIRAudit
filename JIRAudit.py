"""
@Author: Mr128Bit

This is the main module for ATLASAudit.
TODO: Add a description
"""

import sys
import os
import json
import logging
import importlib

from getpass import getpass

import argparse
import urllib3

from bs4 import BeautifulSoup

from cve_utils.cve_utils import *  # pylint: disable=unused-wildcard-import wildcard-import
from score.Manager import *  # pylint: disable=unused-wildcard-import wildcard-import
from apis.jira_api.JiraAPI import JiraAPI  # pylint: disable=unused-wildcard-import
from apis.confluence_api.ConfluenceAPI import ConfluenceAPI 
from apis.marketplace_api.Plugin import *  # pylint: disable=unused-wildcard-import wildcard-import
from Auditor import Auditor  # pylint: disable=unused-wildcard-import
from PluginManager import PluginManager
from misc.Types import AppType
from misc.Color import Color
import misc.Vault
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser(
    prog="ATLASAudit - Jira & Confluence vulnerability scanner",
    description="Scan your jira & confluence instance and get feedback on your configuration and known vulnerabilities",
)
parser.add_argument(
    "-p", "--proxy", help="Tunnel requests through a proxy", required=False
)
parser.add_argument(
    "-u", "--username", help="Your username for websudo authentication", required=False
)
parser.add_argument(
    "-pw", "--password", help="Your password for websudo auth", required=False
)
parser.add_argument(
    "-ip", "--import-plugin", help="Import plugin from marketplace via id", required=False
)
parser.add_argument(
    "-f",
    "--full",
    help="[Jira, Confluence] Start a full scan (authenticated)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-fua",
    "--full-unauth",
    help="[Jira, Confluence] Start a full scan without authentication (only uses unauth-modules)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-fa",
    "--full-auth",
    help="[Jira, Confluence] Start a full scan with authentication (only uses auth-modules)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-d", "--debug", help="Enable debug mode", action="store_true", required=False
)
parser.add_argument(
    "-pe",
    "--plugin-enum",
    help="[Jira, Confluence] Start a plugin enumeration (authenticated)",
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
    help="[Jira, Confluence] Enumerate personal access tokens (authenticated)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-cs",
    "--check-supported-platforms",
    help="[JIRA] Check support of required platforms (authenticated)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-upe",
    "--unauth-plugin-enum",
    help="[Jira, Confluence] Start a plugin enumeration (unauthenticated) ",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-uise",
    "--unauth-issue-status-enum",
    help="[Jira] Start a issue status enumeration (unauthenticated)",
    action="store_true",
    required=False,
)
parser.add_argument(
    "-uue",
    "--unauth-user-enum",
    help="[JIRA] Start an unauthenticated user enumeration",
    metavar="<USERLIST>",
    required=False,
)
parser.add_argument(
    "-ce",
    "--check-exposed-endpoints",
    help="[Jira, Confluence] Check several endpoints for exposed sensitive data and enumerate if possible",
    action="store_true",
)
parser.add_argument(
    "-cc",
    "--check-cves",
    help="[Jira, Confluence] Check if instance version is affected by cve",
    action="store_true",
)
parser.add_argument(
    "-al",
    "--applinks",
    help="[Jira] Get application links for instance (unauthenticated)",
    action="store_true",
)
parser.add_argument(
    "-si",
    "--server-info",
    help="[Jira] Get info about the server (unauthenticated)",
    action="store_true",
)
parser.add_argument(
    "-ve",
    "--vulnerable-endpoints",
    help="[JIRA] Check for vulnerable endpoints (unauthenticated)",
    action="store_true"
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

parser.add_argument(
    "-it",
    "--ignore-templates",
    help="Ignore custom templates and use general template for execution",
    action="store_true",
    required=False,
)

parser.add_argument(
    "-en", 
    "--encrypt", 
    help="Encrypt credentials for the specified template", 
)

parser.add_argument("host", nargs='?', help="Hostname of your jira instance", type=str)

args = parser.parse_args()

TEMPLATE = None
BASE_URL = None
DEBUG_MODE = False
JIRA_PLUGINS_CONFIG = None
CONFLUENCE_PLUGINS_CONFIG = None
SUPPORTED_DATABASES = None
SUPPORTED_JVM = None
EXCLUDED_ENDPOINTS = None
AUTHENTICATED = False
USERNAME = None
PASSWORD = None

from settings import *  # pylint: disable=wrong-import-position wildcard-import unused-wildcard-import

FORMAT = "%(asctime)s [ATLASAudit] %(message)s"
logging.basicConfig(level=LOG_LEVEL, format=FORMAT)

logging.info("Starting client")

proxy = None

if args.password:
    PASSWORD = args.password

if args.host and args.host[-1] == "/":
    BASE_URL = args.host[0:-1]
elif args.host and not args.host[-1] == "/":
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

    banner = f"""

________________________________________________________
                                                  
  ___ _____ _       ___   _____  ___            _ _ _   
 / _ \_   _| |     / _ \ /  ___|/ _ \          | (_) |  
/ /_\ \| | | |    / /_\ \\ `--./ /_\ \_   _  __| |_| |_ 
|  _  || | | |    |  _  | `--. \  _  | | | |/ _` | | __|
| | | || | | |____| | | |/\__/ / | | | |_| | (_| | | |_ 
\_| |_/\_/ \_____/\_| |_/\____/\_| |_/\__,_|\__,_|_|\__|
                                                        
                        
{Color.format('ATLASAudit', Color.CYAN)} - Version: {Color.format('1.1 (alpha)', Color.RED)}   Author: Mr128Bit
{Color.format('Vulnerability Scanner for Jira and Confluence', Color.GREEN)}
________________________________________________________

    """
    print(banner)


def load_config():
    """
    Load all configuration files into json object
    """

    global JIRA_PLUGINS_CONFIG  # pylint: disable=global-statement
    global CONFLUENCE_PLUGINS_CONFIG
    global SUPPORTED_DATABASES  # pylint: disable=global-statement
    global SUPPORTED_JVM  # pylint: disable=global-statement
    global EXCLUDED_ENDPOINTS

    try:
        with open(JIRA_PLUGINS_CONFIG_PATH, "r", encoding="UTF-8") as f:
            jsobj = json.load(f)

            JIRA_PLUGINS_CONFIG = jsobj

        with open(CONFLUENCE_PLUGINS_CONFIG_PATH, "r", encoding="UTF-8") as f:
            jsobj = json.load(f)

            CONFLUENCE_PLUGINS_CONFIG = jsobj
        
        with open(SUPPORTED_DBS_CONFIG_PATH, "r", encoding="UTF-8") as f:
            jsobj = json.load(f)

            SUPPORTED_DATABASES = jsobj

        with open(EXCLUDED_ENDPOINTS_CONFIG_PATH, "r", encoding="UTF-8") as f:
            jsobj = json.load(f)

            EXCLUDED_ENDPOINTS = jsobj

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

    templates = get_templates()

    i_package = None
    template = None

    if args.ignore_templates and "general.py" in templates:
        i_package = "templates.general"
    else:
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

def get_templates():
    
    templates = [
        f
        for f in os.listdir(TEMPLATES_PATH)
        if os.path.isfile(os.path.join(TEMPLATES_PATH, f)) and f != "__init__.py"
    ]
    print(templates)
    return templates


def detect_application_type():

    try:
        response = requests.get(BASE_URL, verify=VERIFY_SSL)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        jira_meta = soup.find('meta', {'name': 'application-name', 'content': 'JIRA'})
        confluence_meta = soup.find('meta', {'name': 'confluence-base-url'})
        
        if jira_meta:
            return AppType.JIRA
        elif confluence_meta:
            return AppType.CONFLUENCE
        else:
            return None
    
    except requests.exceptions.RequestException as e:
        print(e)
        return None



if __name__ == "__main__":
    load_config()

    API = None

    if args.encrypt:
        print("Found '-e,--encrypt' argument, ignoring all other arguments")
        
        template = args.encrypt
        templates = get_templates()
        if not template.endswith(".py"):
            template = f"{template}.py"

        os.path.join(TEMPLATES_PATH, template)

        template_path = [os.path.join(TEMPLATES_PATH, t) for t in templates if template.endswith(t)]

        if template_path:
            print("="*40)
            password = getpass("Input your encryption password: ")
            res = misc.Vault.process_file(template_path[0], password)
            if res:
                print(f"The template {template} was encrypted successfully.")
            else:
                print(f"Nothing to encrypt. The template {template} is already fully encrypted")

            exit()
        else:
            exit()

    if args.import_plugin:
        plugin_manager = PluginManager("", JIRA_PLUGINS_CONFIG, CONFLUENCE_PLUGINS_CONFIG, None, excluded_endpoints=EXCLUDED_ENDPOINTS["exclude_endpoints"])
        plugin_manager.import_plugin(args.import_plugin, AppType.CONFLUENCE)
        exit()

    if not args.host:
        print("Run failed. No host was specified")
        exit(1)

    get_template()

    if hasattr(TEMPLATE, "USER"):
        USERNAME = TEMPLATE.USER
    if hasattr(TEMPLATE, "PASSWORD"):
        PASSWORD = TEMPLATE.PASSWORD

    if not USERNAME and args.username:
        USERNAME = args.username

    if not PASSWORD and args.password:
        PASSWORD = args.password

    app_type = detect_application_type()

    if not app_type:
        print(Color.format("Application type could not be detected. Stopping execution", Color.RED))
        exit(1)

    if USERNAME and PASSWORD:

        if misc.Vault.is_encrypted(data=USERNAME) and misc.Vault.is_encrypted(data=PASSWORD):
            print("="*20)
            print("This template requires a password for encrypting authentication details")
            passw = getpass("Input your encryption password: ")
            USERNAME = misc.Vault.decrypt(USERNAME, passw)
            PASSWORD = misc.Vault.decrypt(PASSWORD, passw)

            if not USERNAME or not PASSWORD:
                print("Wrong decryption password > Decryption failed")

                exit()

        API = None

        if app_type == AppType.JIRA:
            API = JiraAPI(BASE_URL, username=USERNAME, password=PASSWORD)
        else:
            API = ConfluenceAPI(BASE_URL, username=USERNAME, password=PASSWORD, verify_ssl=VERIFY_SSL)

        authenticated = API.init_auth()

        if not authenticated:
            logging.error("Authentication for user %s failed", USERNAME)
            sys.exit(100)
    else:
        if app_type == AppType.JIRA:
            API = JiraAPI(BASE_URL)
        else:
            API = ConfluenceAPI(BASE_URL, verify_ssl=VERIFY_SSL)

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

    if not silent_mode:
        print_banner()

    if args.out:
        path = args.out
    elif RESULTS_PATH:
        path = RESULTS_PATH
    
    print(f"Application Type is {Color.format(app_type.value, Color.CYAN)}")

    auditor = Auditor(
        API,
        TEMPLATE,
        SUPPORTED_DATABASES,
        SUPPORTED_JVM,
        JIRA_PLUGINS_CONFIG,
        CONFLUENCE_PLUGINS_CONFIG,
        app_type,
        results_path=path,
        save_results=save_results,
        silent_mode=silent_mode,
    )
    
    if args.full:
        auditor.full_audit()
    elif args.full_unauth:
        auditor.full_audit_unauth()
    elif args.full_auth:
        auditor.full_audit_auth()
    else:
        if args.server_info:
            if API.authenticated:
                auditor.get_server_info()
            else:
                auditor.get_server_info_unauthenticated()
            auditor.is_servicedesk_installed()
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
        if args.check_exposed_endpoints:
            auditor.check_exposed_sensitive_data()
        if args.check_cves:
            auditor.check_cves()
        if args.applinks:
            auditor.enum_applinks_unauthenticated()
        if args.vulnerable_endpoints:
            auditor.check_vulnerable_endpoints()
    auditor.end_audit()
