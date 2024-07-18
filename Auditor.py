"""
This is the main audit module containing all neccessary methods to start an audit

Author:     @Mr128Bit
Created:    04/24
"""

import logging
import datetime
import json
import uuid

import urllib3
from packaging import version
from settings import *  # pylint: disable=unused-wildcard-import wildcard-import
from score.Manager import *  # pylint: disable=unused-wildcard-import wildcard-import
from misc.Color import Color
from misc.Types import AppType
from apis.marketplace_api.Plugin import *  # pylint: disable=unused-wildcard-import wildcard-import
from apis.jira_api.JiraAPI import JiraRequestException
from cve_utils.cve_utils import *  # pylint: disable=unused-wildcard-import wildcard-import
from bs4 import BeautifulSoup
from PluginManager import PluginManager

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AuditInit:  # pylint: disable=too-few-public-methods
    """
    A decorator class for initializing audits.
    Every audit should have a unique ID and configuration with meta information.
    All methods that save audit data should use this decorator to ensure the presence of a results file.
    """

    def __init__(self, method):
        self.method = method

    def __get__(self, instance, owner):
        if instance is None:
            # Wenn keine Instanz vorhanden ist, gib die Funktion zurück
            return self.method

        def wrapper(*args, **kwargs):
            if not instance.AUDIT_MODE:
                instance.init_audit()
            return self.method(instance, *args, **kwargs)

        return wrapper

    def __call__(self, *args, **kwargs):
        # Da dies der direkt Aufrufbare Teil ist, wende init_audit() an
        instance = args[0]
        if not instance.AUDIT_MODE:
            instance.init_audit()
        return self.method(*args, **kwargs)


class Authenticated:  # pylint: disable=too-few-public-methods
    """
    A decorator class for initializing audits.
    Every audit should have a unique ID and configuration with meta information.
    All methods that save audit data should use this decorator to ensure the presence of a results file.
    """

    def __init__(self, method):
        self.method = method

    def __get__(self, instance, owner):
        def wrapper(*args, **kwargs):
            if not instance.API.authenticated:
                logging.error(
                    "Called method which requires authentication but authentication was not successful. Stopped execution"
                )
                return None
            return self.method(instance, *args, **kwargs)

        return wrapper

class PlatformOnly:
    def __init__(self, *app_types: AppType):
        self.app_types = app_types

    def __call__(self, method):
        def wrapper(instance, *args, **kwargs):
            if instance.APP_TYPE not in self.app_types:
                logging.error(
                    f"Called function for type/s [{','.join([at.value for at in self.app_types])}] but host is {instance.APP_TYPE.value}. Stopped execution"
                )
                return None
            return method(instance, *args, **kwargs)
        return wrapper


class JiraOnly:  # pylint: disable=too-few-public-methods
    """
    A decorator class for initializing audits.
    Every audit should have a unique ID and configuration with meta information.
    All methods that save audit data should use this decorator to ensure the presence of a results file.
    """

    def __init__(self, method):
        self.method = method

    def __get__(self, instance, owner):
        def wrapper(*args, **kwargs):
            if not instance.APP_TYPE == AppType.JIRA:
                logging.error(
                    "Called JiraOnly function but host is no Jira instance. Stopped execution"
                )
                return None
            return self.method(instance, *args, **kwargs)

        return wrapper

class ConfluenceOnly:  # pylint: disable=too-few-public-methods
    """
    A decorator class for initializing audits.
    Every audit should have a unique ID and configuration with meta information.
    All methods that save audit data should use this decorator to ensure the presence of a results file.
    """

    def __init__(self, method):
        self.method = method

    def __get__(self, instance, owner):
        def wrapper(*args, **kwargs):
            if not instance.APP_TYPE == AppType.JIRA:
                logging.error(
                    "Called ConfluenceOnly function but host is no Confluence instance. Stopped execution"
                )
                return None
            return self.method(instance, *args, **kwargs)

        return wrapper

class JiraConfluenceOnly:  # pylint: disable=too-few-public-methods
    """
    A decorator class for initializing audits.
    Every audit should have a unique ID and configuration with meta information.
    All methods that save audit data should use this decorator to ensure the presence of a results file.
    """

    def __init__(self, method):
        self.method = method

    def __get__(self, instance, owner):
        def wrapper(*args, **kwargs):
            if not instance.APP_TYPE in (AppType.JIRA, AppType.CONFLUENCE):
                logging.error(
                    "Called JiraConfluenceOnly Function but host is no Confluence or Jira instance. Stopped execution"
                )
                return None
            return self.method(instance, *args, **kwargs)

        return wrapper

def is_version_affected(affected_version, fix_version, current_version):
    affected_ver = version.parse(affected_version)
    fix_ver = version.parse(fix_version)
    current_ver = version.parse(current_version)
    
    if affected_ver <= current_ver < fix_ver:
        return True
    else:
        return False

class Auditor:  # pylint: disable=too-many-instance-attributes
    """
    A class representing an auditor object.
    An auditor is used to start a test on a jira instance and saves the result either to memory or a json file
    """

    # TODO: maybe i should change the amount of attributes c;
    def __init__(  # pylint: disable=too-many-arguments
        self,
        api,
        template,
        supported_databases,
        supported_jvm,
        jira_plugins_config,
        confluence_plugins_config,
        app_type,
        results_path=None,
        save_results=False,
        silent_mode=False,
    ):
        """
        Constructs all attributes for the auditor object

        Parameters
        ----------
            jira_api : jira_api.JiraAPI
                A jira api object used for authentication and requests
            template : object
                A object representing a custom configuration
            supported_databases : dict
                A dict representing the supported databases configuration
            supported_jvm : dict
                A dict representing the supported jvms configuration
            plugins_config : dict
                A dict representing the plugins configuration
            results_path : str
                The path where results are stored
        """
        # TODO this shouldn't be None, requries check; will do later thiz
        self.API = api
        api.init_auth()
        self.TEMPLATE = template
        self.SUPPORTED_DATABASES = supported_databases
        self.SUPPORTED_JVM = supported_jvm
        self.JIRA_PLUGINS_CONFIG = jira_plugins_config
        self.CONFLUENCE_PLUGINS_CONFIG = confluence_plugins_config
        self.AUDIT_MODE = False
        self.APP_TYPE = app_type
        self.SILENT_MODE = silent_mode
        if results_path:
            self.RESULTS_PATH = Path(results_path)
        else:
            self.RESULTS_PATH = None

        self.AUDIT_ID = str(uuid.uuid4())
        self.RESULT = {}
        self.SAVE_RESULTS = save_results

    def init_audit(self):
        """
        Initializes an audit and saves neccessary meta data in the results file
        """
        start_date = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")
        exec_id = self.AUDIT_ID
        self.AUDIT_MODE = True

        data = {
            "execution_id": exec_id,
            "host": self.API.BASE_URL,
            "exec_user": self.API.USERNAME,
            "start": start_date,
            "end": "",
            "authenticated": self.API.authenticated,
        }

        self.update_results("meta", data)

    def end_audit(self):
        """
        Ends an audit and saves neccessary meta data in the results file
        """
        self.AUDIT_MODE = False

        end_date = datetime.datetime.now().strftime("%d.%m.%Y %H:%M:%S")

        data = self.RESULT.get("meta")
        if data:
            data["end"] = end_date
            self.update_results("meta", data)

        print(f"\n{self.AUDIT_ID}")

    def _print_header(self, title: str):
        sep = int((52 - len(title)) / 2)
        self._print_msg("")
        self._print_msg("_" * sep, f"[{title}]", "_" * sep)
        self._print_msg("")


    def _print_msg(self, *args, **kwargs):
        """
        Prints a message if silent mode isn't set

        Parameters
        ----------
            msg : str
                Message to print
        """

        if not self.SILENT_MODE:
            print(*args, **kwargs)

    def print_plugin_found(
        self, name, version: str = None, vendor: str = None, url: str = None
    ):
        """
        Prints a found plugin

            Parameters:
                name (str):     Name of the plugin
                version (str):  Version of the plugin
                vendor (str):   Name of the plugin's vendor
        """

        if name and vendor:
            self._print_msg(
                f"\n\033[96m[PLUGIN]\033[00m {name}\nVersion: \033[92m{version}\033[00m\nVendor: {vendor}"
            )
            if url:
                self._print_msg(url)

        else:
            self._print_msg(
                f"\n\033[96m[PLUGIN]\033[00m {name}\nVersion: \033[91mUnknown\033[00m\nVendor: \033[91mUnknown\033[00m"
            )

    def update_results(self, key: str, obj):
        """
        Update results of audit and saves data to file if configured

            Parameters:
                key (str):  The key for the results json file
                obj (obj):  A serializable object
        """
        self.RESULT[key] = obj

        if self.SAVE_RESULTS:
            self.save_result()

    def save_result(self):
        """
        Saves the current result to the results json file
        """
        date_str = datetime.datetime.now().strftime("%Y-%m-%d")
        fname = f"{date_str}-{self.AUDIT_ID}.json"

        fpath = self.RESULTS_PATH / fname

        try:
            # create results path if not exist
            if not os.path.isdir(self.RESULTS_PATH):
                os.makedirs(self.RESULTS_PATH)
            with open(fpath, "w", encoding="UTF-8") as f:
                json.dump(self.RESULT, f, indent=4, ensure_ascii=False)

        except OSError as osexc:
            logging.error(
                "[ERROR] An OSError exception was thrown while saving file '%s': %s",
                fpath,
                osexc,
            )
    @PlatformOnly(AppType.JIRA)
    @AuditInit
    def enum_applinks_unauthenticated(self) -> list:
        self._print_header("APPLICATION LINKS")

        response = None
        result = []

        try: 
            response = requests.get(
                f"{self.API.BASE_URL}/rest/menu/latest/appswitcher",
                timeout=10,
                verify=VERIFY_SSL
            )
        except Exception as e: # pylint: disable=broad-exception-caught
            logging.error("User enumeration throw an exception: %s", e)
        
        if response and response.status_code == 200:

            response = [e for e in response.json() if not e.get("self")]
            
            if not response:
                self._print_msg(f"{Color.format('No application links found', Color.RED)}\n")

            else:
                for e in response:
                    key = e.get("key")
                    link = e.get("link")
                    apptype = e.get("applicationType")
                    self._print_msg("")
                    self._print_msg("Key:\t", key)
                    self._print_msg("Link:\t", link)
                    self._print_msg("Type:\t", apptype)
                    self._print_msg("")
                    result.append((key, link, apptype))

        return result

    @PlatformOnly(AppType.JIRA)
    @AuditInit
    def enum_users_unauthenticated(self, user_list: list) -> list:
        """
        This method enumerates users without authentication
        It requires a list of users to work and does not identify if the user is active or inactive

        Parameters
        ----------
            user_list : list
                A list of usernames

        Returns
        -------
            user_found : list
                A list of existing users
        """

        self._print_header("USER ENUM")

        user_found = []

        for user in user_list:
            response = None
            found = False
            
            # https://jira.atlassian.com/browse/JRASERVER-69796
            try: 
                response = requests.get(
                    f"{self.API.BASE_URL}/rest/api/latest/groupuserpicker?query={user}&maxResults=50000",
                    timeout=10,
                    verify=VERIFY_SSL
                )
            except Exception as e: # pylint: disable=broad-exception-caught
                logging.error("User enumeration throw an exception: %s", e)

            if response.status_code == 200:
                response = response.json()
                if response.get("users") and response.get("users").get("users") and len(response["users"]["users"]) > 0:
                    found = True 

            if not found:
                # https://jira.atlassian.com/browse/JRASERVER-71559
                try:
                    response = requests.get(
                        f"{self.API.BASE_URL}/secure/QueryComponentRendererValue!Default.jspa?assignee=user:{user}",
                        timeout=10,
                        verify=VERIFY_SSL
                    )
                except Exception as e: # pylint: disable=broad-exception-caught
                    logging.error("User enumeration throw an exception: %s", e)

                if response.status_code == 200:
                    response = response.json()
                    assignee = response.get("assignee")
                    if assignee and assignee.get("viewHtml") and "An error occurred whilst rendering" not in assignee["viewHtml"]:
                        found = True 

            if not found:
                # https://jira.atlassian.com/browse/JRASERVER-69242
                try:
                    response = requests.get(
                        f"{self.API.BASE_URL}/rest/api/2/user/picker?query={user}",
                        timeout=10,
                        verify=VERIFY_SSL
                    )
                except Exception as e: # pylint: disable=broad-exception-caught
                    logging.error("User enumeration throw an exception: %s", e)
                
                if response.status_code == 200:
                    response = response.json()
                    users = response.get("users")
                    if users:
                        found = True 

            if not found:
                # https://jira.atlassian.com/browse/JRASERVER-71560
                try:
                    response = requests.get(
                        f"{self.API.BASE_URL}/ViewUserHover.jspa?username={user}",
                        timeout=10,
                        verify=VERIFY_SSL
                    )
                except Exception as e: # pylint: disable=broad-exception-caught
                    logging.error("User enumeration throw an exception: %s", e)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.content, 'html.parser')
                    user_details = soup.find('div', class_='user-hover-details')

                    if user_details:
                        user_text = user_details.find('h4').get_text(strip=True)

                        if user_text == user:
                            found = True
            if not found:

                # https://jira.atlassian.com/browse/JRASERVER-71536
                try:
                    response = requests.get(
                        f"{self.API.BASE_URL}/secure/QueryComponent!Jql.jspa?jql=creator={user}",
                        timeout=10,
                        verify=VERIFY_SSL
                    )
                except Exception as e: # pylint: disable=broad-exception-caught
                    logging.error("User enumeration throw an exception: %s", e)

                if response and response.status_code == 401:

                    response = response.json()
                    error_msgs = response.get("errorMessages")

                    if error_msgs and "You are not authorized" in error_msgs[0]:
                        found = True
        
            if found:
                self._print_msg(f"User found: {Color.format(user, Color.GREEN)}\n")
                user_found.append(user)

        self.update_results("unauth_user_enum_found", user_found)

        return user_found

    # Done
    @JiraConfluenceOnly
    @AuditInit
    def enum_plugins_unauthenticated(self):
        """
        Enumerates the plugins without authentication
        """
        pmanager = PluginManager(self.API.BASE_URL, self.JIRA_PLUGINS_CONFIG, self.CONFLUENCE_PLUGINS_CONFIG, self.APP_TYPE)

        try:
            plugins = pmanager.enum_plugins_unauthenticated()
        except PluginManager.PluginEnumerationException as exce:
            logging.error("Plugin enumeration failed: root cause: %s", exce)
            return

        self.update_results("unauth_plugin_enumeration", plugins)

    @JiraOnly
    @AuditInit
    def enum_issue_status_unauthenticated(self):
        """
        Enumerates the issue statuses without authentication
        TODO: implement rating
        """
        self._print_header("ISSUE STATUS")


        querycomponents = None
        try:
            querycomponents = self.API.get_status_unauthenticated()
        except JiraRequestException as exce:
            logging.error(
                "Error while enumeration issue statuses: root cause: %s", exce
            )
            return

        self.update_results("issue_statuses", querycomponents)

        if querycomponents:
            for qc in querycomponents:
                self._print_msg(f"{Color.format('>', Color.CYAN)} {qc}")
    # Done
    @Authenticated
    @AuditInit
    def enum_plugins_authenticated(self, check_versions: bool = False):
        """
        Enumerates all plugins in authenticated mode
        If check_versions is 'True' all versions will be checked and rated

            Parameters:
                check_versions (bool): If false, no version check will be performed
        """

        self._print_header("PLUGINS")


        if check_versions:
            self._print_msg(
                f"{Color.format('Check Versions is enabled, therefore this method may take a few minutes', Color.YELLOW)}\n"
            )

        plugin_list = []

        try:
            plugin_list = self.API.get_plugins(check_versions)
        except JiraRequestException as exce:
            logging.error(
                "An error occured while enumerating plugins: root cause: %s", exce
            )
            return

        plugin_infos = {"check_versions": check_versions, "plugins": []}
        plugins = []

        for plugin in plugin_list:

            diff = None

            if isinstance(plugin, tuple):
                diff = plugin[1]
                plugin = plugin[0]

            name = plugin.name
            vendor = plugin.vendor

            version = plugin.version

            plugin_meta = {
                "name": name,
                "vendor": vendor,
                "version": version,
            }

            if check_versions:
                plugin_meta["versionsBehind"] = diff

            plugins.append(plugin_meta)
            self.print_plugin_found(name, version, vendor)
            score = 0
            score_prefix = "{color}[{status}] [{score}]\033[00m"

            if diff:
                if diff == 0:
                    score = 10
                    self._print_msg(
                        f"{Color.format('[GOOD] [+10]', Color.GREEN)} Plugin is up to date\n"
                    )
                else:
                    if 0 < diff <= 3:
                        score = 0
                        score_prefix = score_prefix.format(
                            color=Color.GREEN.value, status="OK", score=score
                        )
                    elif 3 < diff < 10:
                        score = -5
                        score_prefix = score_prefix.format(
                            color=Color.YELLOW.value, status="NOT GOOD", score=score
                        )
                    elif diff >= 10:
                        score = -10
                        score_prefix = score_prefix.format(
                            color=Color.RED.value, status="BAD", score=score
                        )

                update_score(score, 10)

                if diff > 0:
                    self._print_msg(
                        f"{score_prefix} You are {Color.format(diff, Color.RED)} versions behind | Latest version: {Color.format(plugin.versions[-1], Color.GREEN)}\n"
                    )

        plugin_infos["plugins"] = plugins
        self.update_results("plugins", plugin_infos)

    @JiraConfluenceOnly
    @Authenticated
    @AuditInit
    def enum_personal_access_tokens(self):
        """
        Enumerates personal access tokens in authenticated mode and rates the result
        """

        self._print_header("PERSONAL ACCESS TOKENS")


        pats = []

        try:
            pats = self.API.get_pats()
        except JiraRequestException as exce:
            logging.error(
                "An error occured while retrieving personal access tokens: root cause: %s",
                exce,
            )
            return

        self.update_results("personal_access_token_enumeration", pats)

        for pat in pats:

            name = pat.get("name")
            author = pat.get("author")
            created = pat.get("created")
            expiry = pat.get("expiry")
            last_authenticated = pat.get("last_authenticated")

            self._print_msg(f"\nPAT Name: {Color.format(name, Color.CYAN)}")
            self._print_msg(f"Author: {author}")
            self._print_msg(f"Created: {created}")

            self._print_msg(f"Last authenticated: {last_authenticated}")
            if expiry == "Never":

                prefix = f"[NOT GOOD] [{self.TEMPLATE.PAT_SCORE_NO_EXPIRE}]"

                self._print_msg(
                    f"{Color.format(prefix, Color.YELLOW)} Expiry: {expiry}\n"
                )

                update_score(
                    self.TEMPLATE.PAT_SCORE_NO_EXPIRE, self.TEMPLATE.PAT_SCORE_EXPIRE
                )
            else:

                prefix = f"[GOOD] [+{self.TEMPLATE.PAT_SCORE_EXPIRE}]"

                self._print_msg(
                    f"{Color.format(prefix, Color.GREEN)} Expiry: {expiry}\n"
                )

                update_score(
                    self.TEMPLATE.PAT_SCORE_EXPIRE, self.TEMPLATE.PAT_SCORE_EXPIRE
                )

    @JiraOnly
    @AuditInit
    def check_vulnerable_endpoints(self):
        # < 7.3.5
        # plugins/servlet/oauth/users/icon-uri?consumerUri=
        response = None
        self._print_header("VULNERABLE ENDPOINTS")

        endpoint = "/plugins/servlet/oauth/users/icon-uri?consumerUri=https://google.com"

        try: 
            response = requests.get(
                f"{self.API.BASE_URL}{endpoint}",
                timeout=10,
                verify=VERIFY_SSL
            )
        except Exception as e: # pylint: disable=broad-exception-caught
            logging.error("User enumeration throw an exception: %s", e)

        if response and response.status_code == 200:
            prefix = Color.format(f"[BAD] [{self.TEMPLATE.ENDPOINT_VULNERABLE}]", Color.RED)
            msg = f"Vulnerable endpoint detected: {endpoint}\n>>> CVE-2017-9506 | https://jira.atlassian.com/browse/JRASERVER-65862\n"
            update_score(self.TEMPLATE.ENDPOINT_VULNERABLE, 0)
        else:
            prefix = Color.format(f"[GOOD] [+-0]", Color.GREEN)
            msg = f"Endpoint '{endpoint}' is secure"

        self._print_msg(prefix, msg)


        endpoint = "/secure/ConfigurePortalPages!default.jspa?view=search&searchOwnerUserName=<script>alert(1)</script>&Search=Search"

        try: 
            response = requests.get(
                f"{self.API.BASE_URL}{endpoint}",
                timeout=10,
                verify=VERIFY_SSL
            )
        except Exception as e: # pylint: disable=broad-exception-caught
            logging.error("User enumeration throw an exception: %s", e)

        if response and response.status_code == 200 and "<script>alert(1)</script>" in response.text:
            prefix = Color.format(f"[BAD] [{self.TEMPLATE.ENDPOINT_VULNERABLE}]", Color.RED)
            msg = f"Vulnerable endpoint detected: {endpoint}\n>>> CVE-2019-3402 | https://jira.atlassian.com/browse/JRASERVER-69243\n"
            update_score(self.TEMPLATE.ENDPOINT_VULNERABLE, 0)
        else:
            prefix = Color.format(f"[GOOD] [+-0]", Color.GREEN)
            msg = f"Endpoint '{endpoint}' is secure"
        
        self._print_msg(prefix, msg)

    @JiraConfluenceOnly
    @AuditInit
    def check_exposed_sensitive_data(self): # pylint: disable=too-many-statements
        """
        Checks the instance for exposed endpoints and rates the result
        """

        def eval_result(endpoint, is_exposed):
            score = self.TEMPLATE.EXPOSED_SENSITIVE_DATA
            max_score = score * -1

            if is_exposed:

                prefix = f"[NOT GOOD] [{score}]"
                prefix = Color.format(prefix, Color.YELLOW)

                self._print_msg(
                    f"{prefix} '{endpoint}' is open and exposes possible sensitive data!"
                )
            else:
                score = score * -1
                prefix = f"[GOOD] [{score}]"
                prefix = Color.format(prefix, Color.GREEN)

                self._print_msg(
                    f"{prefix} '{endpoint}' is secure!"
                )

            update_score(score, max_score)

        self._print_header("EXPOSED DATA")

        final_result = {"exposed_urls": []}
        result = None

        try:
            result = self.API.get_status_unauthenticated()
        except JiraRequestException as exce:
            logging.error(
                "An error occured while retrieving issue statuses: root cause: %s", exce
            )

        if result:
            final_result["exposed_urls"].append(self.API.WEB_ENDPOINTS.QUERYCOMPONENT.value)
            final_result["status_enumeration"] = result

            eval_result(self.API.WEB_ENDPOINTS.QUERYCOMPONENT.value, True)
            self._print_msg(Color.format("ATTENTION:", Color.RED), "Not securing this endpoint allows an attacker to enumerate usernames!")
            self._print_msg("More information:\thttps://jira.atlassian.com/browse/JRASERVER-71536\n")
            self._print_msg(Color.format("Found exposed issue status:", Color.YELLOW))
            self._print_msg(result)
        else:
            eval_result(self.API.WEB_ENDPOINTS.QUERYCOMPONENT.value, False)

        # check dashboard exposure

        result = None

        try:
            result = self.API.get_filters_unauthenticated()
        except JiraRequestException as exce:
            logging.error(
                "An error occured while retrieving issue statuses: root cause: %s", exce
            )

        if result:
            final_result["exposed_urls"].append(self.API.WEB_ENDPOINTS.FILTERS.value)
            final_result["filter_enumeration"] = result

            eval_result(self.API.WEB_ENDPOINTS.FILTERS.value, True)
            for filter_ in result:
                self._print_msg("Filter:\t", Color.format(filter_[0], Color.CYAN))
                self._print_msg("ID:\t", Color.format(filter_[1], Color.CYAN), "\n")
        else:
            eval_result(self.API.WEB_ENDPOINTS.FILTERS.value, False)

        result = None

        try:
            result = self.API.get_dashboards_unauthenticated()
        except JiraRequestException as exce:
            logging.error(
                "An error occured while retrieving issue statuses: root cause: %s", exce
            )

        if result:
            final_result["exposed_urls"].append(self.API.API_ENDPOINTS.DASHBOARDS.value)
            final_result["dashboard_enumeration"] = result
            eval_result(self.API.API_ENDPOINTS.DASHBOARDS.value, True)

            for dashboard in result:
                did = dashboard.get("id")
                name = dashboard.get("name")
                url = dashboard.get("view")

                self._print_msg("Dashboard:\t", Color.format(name, Color.CYAN))
                self._print_msg("ID:\t", Color.format(did, Color.CYAN))
                self._print_msg("URL:\t", Color.format(url, Color.CYAN), "\n")

        else:
            eval_result(self.API.API_ENDPOINTS.DASHBOARDS.value, False)

        self.update_results("exposed_sensitive_data_check", final_result)

    @JiraConfluenceOnly
    @Authenticated
    @AuditInit
    def check_supported_platforms(
        self,
    ):  # pylint: disable=too-many-locals too-many-statements
        """
        Check wether all platforms required by jira are supported and rates the result

            Parameters:
                jira_version (str): Jira version to check against
        """

        def check_support(result: str) -> set:
            """
            Returns prefix, color and score based on the support
            """
            pcs = None

            if result == "supported":

                prefix = f"[GOOD] [{self.TEMPLATE.PLATFORM_SUPPORTED}]"
                clr = Color.GREEN
                score = self.TEMPLATE.PLATFORM_SUPPORTED
                pcs = (prefix, clr, score)
            elif result == "deprecated":

                prefix = f"[NOT GOOD] [{self.TEMPLATE.PLATFORM_DEPRECATED}]"
                clr = Color.YELLOW
                score = self.TEMPLATE.PLATFORM_DEPRECATED
                pcs = (prefix, clr, score)

            elif result == "unsupported":

                prefix = f"[BAD] [{self.TEMPLATE.PLATFORM_UNSUPPORTED}]"
                clr = Color.RED
                score = self.TEMPLATE.PLATFORM_UNSUPPORTED
                pcs = (prefix, clr, score)

            if not pcs:
                return None
            return pcs

        platforms = {}
        meta = None

        try:
            meta = self.API.get_server_info()
        except JiraRequestException as exce:
            logging.error("Error while retrieving server info: root cause: %s", exce)
            return

        jira_version = None
        if meta:
            jira_version = meta[0]
        else:
            logging.error("Error while loading server info")
            return

        version = meta[0]

        self._print_msg(
            f"\n{Color.CYAN.value}",
            "_" * 15,
            "[Supported Platforms]",
            "_" * 15,
            f"{Color.ENDFORMAT.value}\n",
        )

        jira_version = ".".join(jira_version.split(".")[0:2])
        db_info = None

        try:
            db_info = self.API.get_database_info()
        except JiraRequestException as exce:
            logging.error("Error while retrieving database info: root cause: %s", exce)
            return

        type_ = db_info.get("type")
        version = db_info.get("version")

        if type_ == self.API.DATABASE.POSTGRESQL:
            version = version.split(".")[0]

            result = self.SUPPORTED_DATABASES[type_.value][version][jira_version]

            platforms["database"] = {
                "type": type_.value,
                "version": version,
                "support": result,
            }

            pcs = check_support(result)

            prefix = pcs[0]
            clr = pcs[1]
            score = pcs[2]

            if clr:
                self._print_msg(
                    f"{Color.format(prefix, clr)} \t Database: {type_.value} version {version} ({Color.format(result, clr)})\n"
                )

                update_score(score, self.TEMPLATE.PLATFORM_SUPPORTED)

        jv_info = None
        # get java info

        try:
            jv_info = self.API.get_jvm_info()
        except JiraRequestException as exce:
            logging.error("Error while retrieving jvm info: root cause: %s", exce)
            return

        vendor = jv_info.get("vendor")
        version = jv_info.get("version")

        if vendor:

            result = self.SUPPORTED_JVM[vendor.value][version][jira_version]
            platforms["java"] = {
                "vendor": vendor.value,
                "version": version,
                "support": result,
            }

            pcs = check_support(result)

            prefix = pcs[0]
            clr = pcs[1]
            score = pcs[2]

            if clr:

                jvm_type = "Oracle JRE/JDK"
                if vendor == self.API.JAVA_VENDOR.ADOPTOPENJDK:
                    jvm_type = "Eclipse Temurin"

                self._print_msg(
                    f"{Color.format(prefix, clr)} \t JVM: {jvm_type} version {version} ({Color.format(result, clr)})\n"
                )
                update_score(score, self.TEMPLATE.PLATFORM_SUPPORTED)

        self.update_results("platforms", platforms)

    @PlatformOnly(AppType.JIRA)
    @AuditInit
    def is_servicedesk_installed(self):
        installed = False

        if self.API.is_servicedesk_installed() and self.API.is_servicedesk_licensed():

            self._print_msg(f"{Color.format('Jira Servicedesk is installed and licensed for use', Color.GREEN)}")
            installed = True
        else:
            self._print_msg(f"{Color.format('Jira Servicedesk is not installed', Color.RED)}")
        
        self.update_results("servicedesk_installed", installed)
        
    # Done
    @PlatformOnly(AppType.JIRA, AppType.CONFLUENCE)
    @AuditInit
    def check_cves(self):
        """
        Check for CVEs for a specific Jira version and updates the result
        """

        self._print_header("VULNERABILITIES")

        cves = []
        version = self.API.get_version()


        if self.APP_TYPE == AppType.JIRA:
            
            if self.API.is_servicedesk_installed() and self.API.is_servicedesk_licensed():

                jsd_version = self.API.calculate_service_desk_version(version)
                self._print_msg("Jira Servicedesk is installed and licensed for use")
                cves = get_cves(jira_sw_version=version, jira_sd_version=jsd_version)
            else:
                self._print_msg("Jira Servicedesk is not installed")
                cves = get_cves(jira_sw_version=version)
        else: 
            cves = get_cves(confluence_version=version)
        vulnlen = len(cves)

        if vulnlen > 0:
            self._print_msg(
                f"\nOh no! I found {Color.format(vulnlen, Color.RED)} known vulnerabilities for your version ({version})"
            )
            self._print_msg(
                Color.format(
                    "I recommend to update your system as soon as possible!",
                    Color.YELLOW,
                ),
                "\n",
            )

            for cve in cves:
                cve_id = cve.get("cve_id")
                severity = cve.get("severity")
                reference = cve.get("reference")

                color = Color.GREY

                if not self.TEMPLATE.VULNERABILITIES_FOUND.get(severity):
                    logging.warning("Unknown severity '{severity}'. Ignoring CVE")
                    continue

                score = self.TEMPLATE.VULNERABILITIES_FOUND[severity]
                update_score(score, 0)

                if severity == "LOW":
                    color = Color.GREEN
                elif severity == "MEDIUM":
                    color = Color.YELLOW
                elif severity in ("HIGH", "CRITICAL"):
                    color = Color.RED

                self._print_msg(
                    f"{Color.format(f'[{severity}] [{score}]', color)} - {Color.format(cve_id, Color.CYAN)} - {reference}"
                )
        else:
            self._print_msg(
                f"{Color.format('[GOOD]', Color.GREEN)} No vulnerabilities for version {Color.format(version, Color.RED)} found!"
            )

        self.update_results("vulnerabilities", cves)

    @JiraConfluenceOnly
    @AuditInit
    def get_server_info_unauthenticated(self):
        meta = None

        try:
            meta = self.API.get_server_info()
        except JiraRequestException as exce:
            logging.error("Error while retrieving server info: root cause: %s", exce)
            return None

        version = meta[0]
        last_update_date = meta[1]
        server_title = meta[2]

        self.update_results(
            "serverInfo",
            {
                "serverTitle": server_title,
                "version": version,
                "lastUpdated": last_update_date,
            },
        )

        self._print_header("INFO")
        # self._print_header("_" * 27, "[INFO]", "_" * 27)
        self._print_msg("")
        self._print_msg(f"Jira Version:\t\t{Color.format(version, Color.CYAN)}")
        self._print_msg(
            f"Last Update Date:\t{Color.format(last_update_date, Color.CYAN)}"
        )
        self._print_msg(f"Server Title:\t\t{Color.format(server_title, Color.CYAN)}\n")

        self._print_msg("")

        return meta

    @JiraConfluenceOnly
    @Authenticated
    @AuditInit
    def get_server_info(self) -> set:
        """
        Get jira server info, updates result with meta data and returns the meta data as set

        Returns
        -------
            meta : set
                Server info of jira instance

        """
        meta = None

        try:
            meta = self.API.get_server_info()
        except JiraRequestException as exce:
            logging.error("Error while retrieving server info: root cause: %s", exce)
            return None

        version = meta[0]
        last_update_date = meta[1]
        server_title = meta[2]

        users = self.API.get_users()
        active_users = users.get("activeUsers")
        inactive_users = users.get("inactiveUsers")

        self.update_results(
            "serverInfo",
            {
                "serverTitle": server_title,
                "version": version,
                "lastUpdated": last_update_date,
            },
        )
        self.update_results(
            "userInfo", {"activeUsers": active_users, "inactiveUsers": inactive_users}
        )

        self._print_header("INFO")
        self._print_msg("")
        self._print_msg(f"Jira Version:\t\t{Color.format(version, Color.CYAN)}")
        self._print_msg(
            f"Last Update Date:\t{Color.format(last_update_date, Color.CYAN)}"
        )
        self._print_msg(f"Server Title:\t\t{Color.format(server_title, Color.CYAN)}\n")
        self._print_msg("User information:")
        self._print_msg(f"Active:\t\t{Color.format(len(active_users), Color.CYAN)}")
        self._print_msg(f"Inactive:\t{Color.format(len(inactive_users), Color.CYAN)}")
        self._print_msg(
            f"Total:\t\t{Color.format(len(inactive_users) + len(active_users), Color.CYAN)}"
        )
        self._print_msg("")

        return meta

    @JiraConfluenceOnly
    @Authenticated
    @AuditInit
    def full_audit_auth(self):
        """
        Start a full audit in authenticated mode
        Prints a score after execution
        """
        # get server info
        meta = self.get_server_info()
        version = meta[0]
        # get cves
        self.check_cves()

        # enumerate plugins (authenticated)
        self.enum_plugins_authenticated(check_versions=True)

        # enumerate personal access tokens
        self.enum_personal_access_tokens()

        # check supported platforms
        self.check_supported_platforms()

        self.check_exposed_sensitive_data()

        # print score
        print_score()

    @JiraConfluenceOnly
    @AuditInit
    def full_audit_unauth(self):
        """
        Start a full audit in unauthenticated mode
        Prints no score after execution
        """
        # TODO: add unatuh get_server_info method
        # meta = self.get_server_info()
        # version = meta[0]
        # get cves
        # self.check_cves(version)
        self.enum_applinks_unauthenticated()

        self.enum_plugins_unauthenticated()

        self.check_exposed_sensitive_data()


    @JiraConfluenceOnly
    @Authenticated
    @AuditInit
    def full_audit(self):
        """
        Start full audit mode (authentication & websudo required)
        Prints a score after execution
        """

        logging.info("Starting full audit mode...")

        # get server info
        meta = self.get_server_info()
        version = meta[0]
        # get cves
        self.check_cves()

        # enumerate plugins (authenticated)
        self.enum_plugins_authenticated(check_versions=True)

        self.enum_plugins_unauthenticated()

        # enumerate personal access tokens
        self.enum_personal_access_tokens()

        # check supported platforms
        self.check_supported_platforms()

        self.check_exposed_sensitive_data()

        # print score
        print_score()
