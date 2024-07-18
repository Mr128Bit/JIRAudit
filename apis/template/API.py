import requests
from http.cookies import SimpleCookie
import logging
import os
from bs4 import BeautifulSoup

from requests.adapters import HTTPAdapter, Retry
from apis.marketplace_api.Plugin import *  # pylint: disable=unused-wildcard-import wildcard-import

class API():
    def __init__(self, base_url: str, username: str = None, password: str = None, verify_ssl=True):

        self.USERNAME = username
        self.PASSWORD = password
        self.BASE_URL = base_url
        self.VERIFY_SSL = verify_ssl
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
        self.SESSION.mount("http://", HTTPAdapter(max_retries=retries))

        self.WEB_ENDPOINTS = None
        self.API_ENDPOINTS = None


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

    def authenticate_as_admin(self):
        pass

    def websudo_request(self, url):
        pass

    def get_plugins(self, check_versions: bool = False) -> list:
        return []

    def init_auth(self) -> bool:
        return False
    
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
    
    def get_plugins_raw(self) -> dict:
        """
        Gets all plugins from the system in raw format (requires authentication)

        Returns
        ------
            response : dict
                A dict representing the json response
        """

        response = self.websudo_request("/rest/plugins/1.0/")
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

    def get_version(self):

        response = requests.get(self.BASE_URL, verify=self.VERIFY_SSL)
        soup = BeautifulSoup(response.content, 'html.parser')

        meta = soup.find('meta', {'name': 'ajs-version-number'})
        version = meta.get('content')  

        return version