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

from settings import *  # pylint: disable=unused-wildcard-import wildcard-import
from score.Manager import *  # pylint: disable=unused-wildcard-import wildcard-import
from misc.Color import Color
from jira_api.marketplace_api.Plugin import *  # pylint: disable=unused-wildcard-import wildcard-import
from jira_api.JiraAPI import JiraRequestException
from cve_utils.cve_utils import *  # pylint: disable=unused-wildcard-import wildcard-import
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
        # Da dies der direkt aufrufbare Teil ist, wende init_audit() an
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
            if not instance.JIRA_API.authenticated:
                logging.error(
                    "Called method which requires authentication but authentication was not successful. Stopped execution"
                )
                return None
            return self.method(instance, *args, **kwargs)

        return wrapper


class Auditor:  # pylint: disable=too-many-instance-attributes
    """
    A class representing an auditor object.
    An auditor is used to start a test on a jira instance and saves the result either to memory or a json file
    """

    # TODO: maybe i should change the amount of attributes c;
    def __init__(  # pylint: disable=too-many-arguments
        self,
        jira_api,
        template,
        supported_databases,
        supported_jvm,
        plugins_config,
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
        self.JIRA_API = jira_api
        if not jira_api.authenticated:
            jira_api.init_auth()
        self.TEMPLATE = template
        self.SUPPORTED_DATABASES = supported_databases
        self.SUPPORTED_JVM = supported_jvm
        self.PLUGINS_CONFIG = plugins_config
        self.AUDIT_MODE = False
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
            "host": self.JIRA_API.BASE_URL,
            "exec_user": self.JIRA_API.USERNAME,
            "start": start_date,
            "end": "",
            "authenticated": self.JIRA_API.authenticated,
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

        print(self.AUDIT_ID)

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

            with open(fpath, "w", encoding="UTF-8") as f:
                json.dump(self.RESULT, f, indent=4)

        except OSError as osexc:
            logging.error(
                "[ERROR] An OSError exception was thrown while saving file '%s': %s",
                fpath,
                osexc,
            )

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

        self._print_msg("\n\033[97m", "_" * 24, "[User Enum]", "_" * 24, "\033[00m\n")

        user_found = []

        for user in user_list:

            response = requests.get(
                f"{self.JIRA_API.BASE_URL}/secure/QueryComponent!Jql.jspa?jql=creator={user}",
                timeout=10,
            )

            if response.status_code == 401:

                response = response.json()
                error_msgs = response.get("errorMessages")

                if error_msgs and "You are not authorized" in error_msgs[0]:
                    user_found.append(user)
                    self._print_msg(f"User found: {Color.format(user, Color.CYAN)}\n")

        self.update_results("unauth_user_enum_found", user_found)

        return user_found

    @AuditInit
    def enum_plugins_unauthenticated(self):
        """
        Enumerates the plugins without authentication
        """

        pmanager = PluginManager(self.JIRA_API.BASE_URL, self.PLUGINS_CONFIG)

        try:
            plugins = pmanager.enum_plugins_unauthenticated()
        except PluginManager.PluginEnumerationException as exce:
            logging.error("Plugin enumeration failed: root cause: %s", exce)
            return

        self.update_results("unauth_plugin_enumeration", plugins)

    @AuditInit
    def enum_issue_status_unauthenticated(self):
        """
        Enumerates the issue statuses without authentication
        TODO: implement rating
        """
        self._print_msg(
            "\n\033[97m", "_" * 19, "[Customfields]", "_" * 19, "\033[00m\n"
        )

        querycomponents = None
        try:
            querycomponents = self.JIRA_API.get_status_unauthenticated()
        except JiraRequestException as exce:
            logging.error(
                "Error while enumeration issue statuses: root cause: %s", exce
            )
            return

        self.update_results("issue_statuses", querycomponents)

        if querycomponents:
            for qc in querycomponents:
                self._print_msg(f"{Color.format('>', Color.CYAN)} {qc}")

    @Authenticated
    @AuditInit
    def enum_plugins_authenticated(self, check_versions: bool = False):
        """
        Enumerates all plugins in authenticated mode
        If check_versions is 'True' all versions will be checked and rated

            Parameters:
                check_versions (bool): If false, no version check will be performed
        """

        self._print_msg("\n\033[97m", "_" * 24, "[Plugins]", "_" * 24, "\033[00m\n")

        if check_versions:
            self._print_msg(
                f"{Color.format('Check Versions is enabled, therefore this method may take a few minutes', Color.YELLOW)}\n"
            )

        plugin_list = []

        try:
            plugin_list = self.JIRA_API.get_plugins(check_versions)
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

    @Authenticated
    @AuditInit
    def enum_personal_access_tokens(self):
        """
        Enumerates personal access tokens in authenticated mode and rates the result
        """

        self._print_msg(
            f"\n{Color.PURPLE.value}",
            "_" * 15,
            "[Personal Access Tokens]",
            "_" * 15,
            f"{Color.ENDFORMAT.value}\n",
        )

        pats = []

        try:
            pats = self.JIRA_API.get_pats()
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

    @Authenticated
    @AuditInit
    def check_exposed_sensitive_data(self):
        """
        Checks the instance for exposed endpoints and rates the result
        """

        self._print_msg(
            "\n\033[97m", "_" * 19, "[Exposed Data]", "_" * 19, "\033[00m\n"
        )

        result = None

        try:
            result = self.JIRA_API.get_status_unauthenticated()
        except JiraRequestException as exce:
            logging.error(
                "An error occured while retrieving issue statuses: root cause: %s", exce
            )
            return

        score = self.TEMPLATE.EXPOSED_SENSITIVE_DATA
        max_score = score * -1

        if result:

            prefix = f"[NOT GOOD] [{score}]"
            prefix = Color.format(prefix, Color.YELLOW)

            self._print_msg(
                f"{prefix} '{self.JIRA_API.WEB_ENDPOINTS.QUERYCOMPONENT.value}' is open and exposes possible sensitive data!"
            )
        else:
            score = score * -1
            prefix = f"[GOOD] [{score}]"
            prefix = Color.format(prefix, Color.GREEN)

            self._print_msg(
                f"{prefix} '{self.JIRA_API.WEB_ENDPOINTS.QUERYCOMPONENT.value}' is secure!"
            )

        update_score(score, max_score)

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
            meta = self.JIRA_API.get_server_info()
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
            db_info = self.JIRA_API.get_database_info()
        except JiraRequestException as exce:
            logging.error("Error while retrieving database info: root cause: %s", exce)
            return

        type_ = db_info.get("type")
        version = db_info.get("version")

        if type_ == self.JIRA_API.DATABASE.POSTGRESQL:
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
            jv_info = self.JIRA_API.get_jvm_info()
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
                if vendor == self.JIRA_API.JAVA_VENDOR.ADOPTOPENJDK:
                    jvm_type = "Eclipse Temurin"

                self._print_msg(
                    f"{Color.format(prefix, clr)} \t JVM: {jvm_type} version {version} ({Color.format(result, clr)})\n"
                )
                update_score(score, self.TEMPLATE.PLATFORM_SUPPORTED)

        self.update_results("platforms", platforms)

    @AuditInit
    def check_cves(self, version: str):
        """
        Check for CVEs for a specific Jira version and updates the result
        """

        self._print_msg(
            f"\n{Color.RED.value}",
            "_" * 20,
            "[Vulnerabilities]",
            "_" * 20,
            f"{Color.ENDFORMAT.value}\n",
        )

        jsd_version = self.JIRA_API.calculate_service_desk_version(version)
        cves = get_cves(version, jira_sd_version=jsd_version)

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
            meta = self.JIRA_API.get_server_info()
        except JiraRequestException as exce:
            logging.error("Error while retrieving server info: root cause: %s", exce)
            return None

        version = meta[0]
        last_update_date = meta[1]
        server_title = meta[2]

        users = self.JIRA_API.get_users()
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

        self._print_msg("_" * 27, "[INFO]", "_" * 27)
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
        self.check_cves(version)

        # enumerate plugins (authenticated)
        self.enum_plugins_authenticated(check_versions=True)

        # enumerate personal access tokens
        self.enum_personal_access_tokens()

        # check supported platforms
        self.check_supported_platforms()

        self.check_exposed_sensitive_data()

        # print score
        print_score()

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

        self.enum_plugins_unauthenticated()

        self.check_exposed_sensitive_data()

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
        self.check_cves(version)

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
