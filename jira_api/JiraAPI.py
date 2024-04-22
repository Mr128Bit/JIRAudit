"""
This module represents a JIRA API in python, including official and inoffical functions

Author:     Mr128Bit
Created:    04/24

"""

from enum import Enum
from http.cookies import SimpleCookie
import os
import re
import logging

import requests
from lxml import etree
import urllib3

from .marketplace_api.Plugin import *  # pylint: disable=unused-wildcard-import wildcard-import


logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class AuthenticationFailedException(Exception):
    """
    Exception thrown if authentication with jira failed
    """

    def __init__(self, message="Authentication for user failed", errors=None):
        super().__init__(message)
        self.errors = errors


class JiraRequestException(Exception):
    """
    Exception thrown if a request to jira failed with any reason
    """

    def __init__(self, message="Jira request failed", errors=None):
        super().__init__(message)
        self.errors = errors


class JiraAPI:  # pylint: disable=too-many-public-methods too-many-instance-attributes
    """
    This class represents an interface between Jira and Python

    Attributes
    ----------
    base_url : str
    username : str
    password : str

    Methods
    -------
    TODO
    """

    class API_ENDPOINTS(Enum):
        """
        An enum class listing all used official jira api endpoints in this api
        """

        SERVERINFO = "/rest/api/latest/serverInfo"
        PLUGIN_INFO = "/rest/plugins/1.0/"
        SEARCH_USER = "/rest/api/2/user/search"
        MYSELF = "/rest/api/latest/myself"
        AUTH = "/rest/auth/1/session"
        DASHBOARDS = "/rest/api/2/dashboard?maxResults=100"

    class WEB_ENDPOINTS(Enum):
        """
        An enum class listing all used jira web endpoints in this api
        This endpoints are used, when no API endpoint is available
        """

        SYSTEMINFO = "/secure/admin/ViewSystemInfo.jspa"
        WEBSUDO = "/secure/admin/WebSudoAuthenticate.jspa"
        LOGIN = "/login.jsp"
        QUERYCOMPONENT = "/secure/QueryComponent!Default.jspa"
        USERBROWSER = "/secure/admin/user/UserBrowser.jspa"

    class DATABASE(Enum):
        """
        An enum class listing all supported database types for jira
        """

        POSTGRESQL = "PostgreSQL"
        MYSQL = "MySQL"
        ORACLE = "Oracle"
        AURORA = "Amazon Aurora"
        AZURE = "Microsoft Azure"
        AZURE_PSQL = "Azure Database for PostgreSQL"

    class JAVA_VENDOR(Enum):
        """
        An enum class listing all supported java types for jira
        """

        ADOPTOPENJDK = "AdoptOpenJDK"
        ORACLE = "Oracle"

    def __init__(self, base_url: str, username: str = None, password: str = None):
        """
        Custructs all necessary attributes for the API object

        Parameters
        ----------
            base_url : str
                The Baseurl of the jira instance including the protocol (http/https)
            username : str, optional
                The username used for authentication (requires admin privileges)
            password : str, optional
                The password used for authentication
        """
        self.USERNAME = username
        self.PASSWORD = password
        self.BASE_URL = base_url
        self.HEADERS = {}
        # TODO: put this in a config
        self.ATLASSIAN_VENDOR_NAMES = [
            "Atlassian",
            "Atlassian Community",
            "Atlassian Software Systems Pty Ltd",
            "The Apache Software Foundation",
            "Atlassian Pty Ltd.",
            "Atlassian Pty Ltd",
            "Atlassian Software Systems",
        ]
        self.IGNORE_PLUGIN_VENDORS = [
            "Sun Microsystems",
            "SpringSource",
            "OSGi Alliance http://www.osgi.org/",
            "(unknown)",
        ]

        self.JIRA_HEADER = {"X-Atlassian-Token": "no-check"}
        self.COOKIES_FILE = "session.cookie"
        self.SESSION_COOKIE = None
        self._AUTHENTICATED = False

        self.SESSION = requests.Session()

        retries = Retry(
            total=6, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]
        )

        self.SESSION.mount("https://", HTTPAdapter(max_retries=retries))

    @property
    def authenticated(self):
        """
        Getter function for the attribute _AUTHENTICATED
        This attribute gives information wether the API is authenticated or not

        Returns
        -------
            _AUTHENTICATED : bool
                If this attributes equals 'True', the API is already authenticated
        """
        return self._AUTHENTICATED

    def parse_cookies(self):
        """
        This function parses the cookie-string (if authenticated) and returns a dict representing the cookies for a request

        Returns
        -------
            cookies : dict
                Returns a dict containing the parsed cookie string
                If the cookie string isn't set, it returns None
        """

        cookies = None

        if self.SESSION_COOKIE:
            cookie = SimpleCookie()

            cookie.load(self.SESSION_COOKIE)

            cookies = {key: value.value for key, value in cookie.items()}

        return cookies

    def get_session_cookies(self, force: bool = False):
        """
        This function retrieves a cookie used for future requests.
        If session cookie is set, it will not be overwritten unless the force parameter is set to 'True'

        Parameters
        ----------
            force : bool, optional
                If this parameter is set to 'True' the old cookie will be overwritten
        """

        if not self.SESSION_COOKIE and not force:

            url = f"{self.BASE_URL}{self.API_ENDPOINTS.AUTH.value}"
            response = self.SESSION.get(
                url, auth=(self.USERNAME, self.PASSWORD), headers=self.JIRA_HEADER
            )
            response.raise_for_status()

            try:
                with open(self.COOKIES_FILE, "w", encoding="UTF-8") as f:
                    c = ""
                    for cookie in response.cookies:
                        cstr = f"{cookie.name}={cookie.value};"
                        c += cstr
                        f.write(cstr)
                    self.SESSION_COOKIE = c
            except Exception as e:  # pylint: disable=broad-exception-caught
                # session cookie is unused at the moment
                logging.error("Could not save cookies file: %s", e)

    def websudo_request(self, url: str) -> requests.models.Response:
        """
        This function generates a GET websudo request against an endpoint (requires authentication first)

        Parameters
        ----------
            url : str
                Endpoint used for request without leading base url

        Returns
        -------
            response : requests.models.Response
                A response object from the websudo request

        Raises
        ------
            JiraRequestException : If status code is not 200 or the request threw any exception
        """

        requrl = f"{self.BASE_URL}{self.WEB_ENDPOINTS.WEBSUDO.value}"

        payload = {
            "webSudoPassword": self.PASSWORD,
            "os_cookie": "true",
            "webSudoIsPost": "false",
            "authenticate": "Confirm",
            "webSudoDestination": url,
        }

        cookies = self.parse_cookies()
        response = None

        try:
            response = self.SESSION.post(
                requrl, data=payload, headers=self.JIRA_HEADER, cookies=cookies
            )
            response.raise_for_status()

            status_code = response.status_code

            if status_code != 200:
                raise JiraRequestException(
                    message=f"Request resulted in HTTP status {status_code}"
                )

        except Exception as e:
            raise JiraRequestException(message=f"Request thorw an exception {e}") from e

        return response

    def authenticate_as_admin(self):
        """
        Authenticates the user for future requests (requires admin privileges)

        Raises
        ------
            JiraRequestException : If status code is not 200 or the request threw any exception

        """

        url = f"{self.BASE_URL}{self.WEB_ENDPOINTS.WEBSUDO.value}"

        payload = {
            "webSudoPassword": self.PASSWORD,
            "os_cookie": "true",
            "webSudoIsPost": "false",
            "authenticate": "Confirm",
        }

        cookies = self.parse_cookies()

        try:
            response = self.SESSION.post(
                url, data=payload, headers=self.JIRA_HEADER, cookies=cookies
            )
            response.raise_for_status()
            status_code = response.status_code

            if status_code != 200:
                raise JiraRequestException(
                    message=f"Request resulted in HTTP status {status_code}"
                )

        except Exception as e:
            raise JiraRequestException(message=f"Request thorw an exception {e}") from e

    def init_auth(self) -> bool:
        """
        Initiates the authentication for the api (requires admin privileges)
        This function supresses any exceptions and just returns if the authentication was successful

        Returns
        -------
            True : If authentication was successful
            False : If authentication failed with any reason
        """

        try:
            if not self.authenticated:
                self.get_session_cookies()
                self.authenticate_as_admin()

                self._AUTHENTICATED = True
        except:  # pylint: disable=bare-except
            return False

        return True

    def calculate_service_desk_version(self, jira_version: str) -> str:
        """
        Get the service desk version based on a jira software version

        Parameters
        ----------
            jira_version : str
                Jira software version

        Returns
        -------
            service_desk_version : str
                Jira service desk version
        """

        parts = jira_version.split(".")
        major_version = int(parts[0])
        minor_version = int(parts[1])

        service_desk_version = f"{major_version - 4}.{minor_version}"

        return service_desk_version

    """
    # not ready yet
    def get_users_failed_logins_test(self):

        response = self.websudo_request(self.WEB_ENDPOINTS.USERBROWSER.value)

        html_element = etree.HTML(response.text)

        element = html_element.xpath("//span[@class='results-count-total']")
        count = element[0].text
        count = int(count)

        index_max = int(count / 100)

        for i in range(1, index_max + 1):
            url = f"/secure/admin/user/UserBrowser.jspa?start={i*100}&activeFilter=false&max=100"

            response = self.websudo_request(url)
            html = etree.HTML(response.text)

            rows = html.xpath("//tr[@class='vcard user-row']")

            for row in rows:

                login_details = row.find(".//td[@data-cell-type='login-details']")

                if login_details:
                    details = "".join(login_details.xpath(".//text()"))

                    if "Current failed logins" in details:

                        user = row.find(".//span[@class='fn']")
                        if user:
                            ...
    """

    def delete_cookies_file(self) -> bool:
        """
        Deletes the cookie file

        Returns
        -------
            True : If cookie file was succesfully deleted
            False : If cookie file did not exist
        """

        if os.path.exists(self.COOKIES_FILE):
            os.remove(self.COOKIES_FILE)
            return True

        return False

    def get_server_info_raw(self) -> dict:
        """
        Get the raw  server info of the jira instance

        Returns
        -------
            response : dict
                A dict representing the json response

        """

        response = self.websudo_request(self.API_ENDPOINTS.SERVERINFO.value)
        response = response.json()

        return response

    def get_server_info(self) -> set:
        """
        Get version, buildDate and serverTitle from raw server info object

        Returns
        -------
            server_info : A set containing version, last update date and server title

        """

        response = self.get_server_info_raw()

        version = response.get("version")
        last_update = response.get("buildDate")
        server_title = response.get("serverTitle")

        server_info = (version, last_update, server_title)

        return server_info

    def get_plugins_raw(self) -> dict:
        """
        Gets all plugins from the system in raw format (requires authentication)

        Returns
        ------
            response : dict
                A dict representing the json response
        """

        response = self.websudo_request(self.API_ENDPOINTS.PLUGIN_INFO.value)
        response = response.json()

        return response

    def get_plugins(self, check_versions: bool = False) -> list:
        """
        Gets all plugins name, version, key and vendor information (requires authentication)

        Parameters
        ----------
            check_versions : bool, optional
                Checks the versions against new updates (might delay the execution for minutes)

        Returns
        -------
            result : list
                A list containing sets of plugin information
        """
        plugins = self.get_plugins_raw()
        result = []

        for plugin in plugins.get("plugins"):

            version = plugin.get("version")
            key = plugin.get("key")
            vendor = plugin.get("vendor")

            if vendor:
                vendor = vendor.get("name")
            if vendor and (
                vendor not in self.ATLASSIAN_VENDOR_NAMES
                and vendor not in self.IGNORE_PLUGIN_VENDORS
            ):

                plugin = Plugin(key, version=version, check_versions=check_versions)

                if plugin.is_marketplace_app:

                    if hasattr(plugin, "versions"):

                        versions = plugin.versions
                        versions.reverse()

                        diff = plugin.check_version(version)

                        result.append((plugin, diff))
                    else:
                        result.append(plugin)

        return result

    def get_users(self):
        """
        Gets all the inactive and active users on the system (requires authentication)

        Returns
        -------
            users : dict
                A dictonary containing a list of active and inactive users
        """

        start_at = 0
        active_users = []
        inactive_users = []

        while True:
            response = self.websudo_request(
                f"{self.API_ENDPOINTS.SEARCH_USER.value}?username=.&maxResults=1000&includeInactive=True&startAt={start_at}"
            )

            user_list = eval(
                response.text.replace("false", "False").replace("true", "True")
            )

            for user in user_list:
                if user.get("active"):
                    active_users.append(user)
                else:
                    inactive_users.append(user)

            if len(user_list) == 1000:
                start_at += 1000
            else:
                break

        users = {"activeUsers": active_users, "inactiveUsers": inactive_users}

        return users

    def get_pats(self) -> list:
        """
        Gets all personal access tokens with name, author, creation date, expiring date and date of last authentication

        Returns
        -------
            tokens : list
                A list of dictonaries containing information about the tokens

        """

        tokens = []

        try:
            payload = {"page": 0, "limit": 100, "name": "", "userKeys": []}

            headers = {
                "Accept-Language": "de,en-US;q=0.7,en;q=0.3",
                "Content-Type": "application/json",
                "Connection": "keep-alive",
                "X-Atlassian-Token": "nocheck",
            }

            response = self.SESSION.post(
                f"{self.BASE_URL}/rest/pat/latest/tokens/search",
                cookies=self.parse_cookies(),
                headers=headers,
                json=payload,
            )

            response = response.json()

            values = response.get("values")

            for e in values:
                user = e.get("userProfileResource").get("username")
                name = e.get("name")
                created_at = e.get("createdAt")
                lastAccessed = e.get("lastAccessedAt")
                expiring = e.get("expiringAt")
                if expiring.startswith("9999"):
                    expiring = "Never"

                token = {
                    "name": name,
                    "author": user,
                    "created": created_at,
                    "expiry": expiring,
                    "last_authenticated": lastAccessed,
                }
                tokens.append(token)

        except Exception as e:
            raise JiraRequestException(message=f"Request throw an exception {e}") from e

        return tokens

    def get_dashboards_unauthenticated(self) -> list:
        """
        List dashboards unauthenticated if the endpoint is not secured

        Returns
        -------
            result : list
                A list containing all dashboards
        """
        result = []

        try:
            response = requests.get(f"{self.BASE_URL}{self.WEB_ENDPOINTS}", timeout=10)
            if response.status_code == 200:
                response = response.json()

                dashboards = response.get("dashboards")
                if dashboards:
                    result = dashboards
        except Exception as e:
            raise JiraRequestException(message=f"Request throw an exception {e}") from e

        return result

    def get_status_unauthenticated(self) -> list:
        """
        # https://confluence.atlassian.com/jirakb/how-to-control-anonymous-user-access-in-a-public-jira-instance-975031479.html
        # https://jira.atlassian.com/browse/JRASERVER-71536

        Gets the issue statuses of an instance without authentication

        Returns
        -------
            result : list
                A list containing available status for issues
                The list is empty if the request failed
        """

        result = []

        try:
            response = requests.get(
                f"{self.BASE_URL}{self.WEB_ENDPOINTS.QUERYCOMPONENT.value}",
                verify=False,
                timeout=10,
            )
            response = response.json()

            html = response["values"]["status"]["editHtml"]
            result = re.findall(r"<option[^>]*>\s*([^<]+)\s*<\/option>", html)
        except Exception as e:
            raise JiraRequestException(message=f"Request thorw an exception {e}") from e

        return result

    def get_database_info(self) -> dict:
        """
        Gets database type and version of jira (requires authentication)

        Returns
        -------
            db_info : dict
                A dictionary containing database type and version
        """

        url = f"{self.BASE_URL}{self.WEB_ENDPOINTS.SYSTEMINFO.value}"

        response = self.websudo_request(url)

        html = etree.HTML(response.text)

        type_element = html.xpath(
            "//td[strong[text()='Database type']]/following-sibling::td[@class='cell-type-value']"
        )
        version_element = html.xpath(
            "//td[strong[text()='Database version']]/following-sibling::td[@class='cell-type-value']"
        )
        type_ = None
        version = None

        db_type = type_element[0].text
        db_version = version_element[0].text

        version = db_version.split(" ")[0]

        if re.match(r".*azure.*", db_type, re.IGNORECASE) and re.match(
            r".*postgres.*", db_type, re.IGNORECASE
        ):
            type_ = self.DATABASE.AZURE_PSQL
        elif re.match(r".*postgres.*", db_type, re.IGNORECASE):
            type_ = self.DATABASE.POSTGRESQL
        elif re.match(r".*mysql.*", db_type, re.IGNORECASE):
            type_ = self.DATABASE.MYSQL
        elif re.match(r".*oracle.*", db_type, re.IGNORECASE):
            type_ = self.DATABASE.ORACLE
        elif re.match(r".*amazon.*", db_type, re.IGNORECASE) or re.match(
            r".*aurora.*", db_type, re.IGNORECASE
        ):
            type_ = self.DATABASE.AURORA
        elif re.match(r".*azure.*", db_type, re.IGNORECASE) or re.match(
            r".*microsoft.*", db_type, re.IGNORECASE
        ):
            type_ = self.DATABASE.AZURE

        db_info = {"type": type_, "version": version}

        return db_info

    def get_jvm_info(self) -> dict:
        """
        Get information about the java virtual machine (authentication required)

        Returns
        -------
            jv_info : dict
                A dictionary containing the vendor and version of the jvm
        """

        url = f"{self.BASE_URL}{self.WEB_ENDPOINTS.SYSTEMINFO.value}"

        response = self.websudo_request(url)

        html = etree.HTML(response.text)

        vendor_element = html.xpath(
            "//td[strong[text()='Java Vendor']]/following-sibling::td[@class='cell-type-value']"
        )
        version_element = html.xpath(
            "//td[strong[text()='JVM Version']]/following-sibling::td[@class='cell-type-value']"
        )
        vendor = None

        jv_vendor = vendor_element[0].text
        version = version_element[0].text

        if "adopt" in jv_vendor.lower():
            vendor = self.JAVA_VENDOR.ADOPTOPENJDK
        elif "oracle" in jv_vendor.lower():
            vendor = self.JAVA_VENDOR.ORACLE

        jv_info = {"vendor": vendor, "vendor_string": jv_vendor, "version": version}

        return jv_info

    def get_myself(self) -> requests.models.Response:
        """
        Gets information about the authenticated user

        TODO
        """
        response = None

        try:
            url = f"{self.BASE_URL}{self.API_ENDPOINTS.MYSELF.value}"
            resp = requests.get(url=url, verify=False, headers=self.HEADERS, timeout=10)
            if resp.status_code == 200:
                response = resp.json()
            else:
                raise JiraRequestException(
                    message=f"Request resulted in HTTP status {resp.status_code}"
                )
        except Exception as e:
            raise JiraRequestException(message=f"Request thorw an exception {e}") from e

        return response
