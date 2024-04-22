"""
This module is part of the Atlassian marketplace API 
A Plugin object represents an marketplace / JIRA Plugin

Author:     @Mr128Bit
Created:    04/24
"""

import logging

import requests
from requests.adapters import HTTPAdapter, Retry

from .Settings import API_URL
from .MarketplaceRequestException import MarketplaceRequestException


class Plugin:
    """
    This class represents a JIRA-Plugin
    """

    def __init__(self, key, version: str = None, check_versions: bool = False):
        self.key = key
        self.version = version
        self.session = requests.Session()

        retries = Retry(
            total=6, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504]
        )

        self.session.mount("https://", HTTPAdapter(max_retries=retries))

        if self.is_marketplace_app:
            resp = None
            try:
                resp = self.session.get(f"{API_URL}/addons/{self.key}", timeout=10)

                if resp.status_code == 200:
                    self.object = resp.json()

                    self.name = self.load_name()
                    self.vendor = self.load_vendor()
                else:
                    raise MarketplaceRequestException(
                        message=f"Request resulted in HTTP status {resp.status_code}"
                    )

            except Exception as exce:
                raise MarketplaceRequestException(
                    message=f"Request throw an exception {exce}"
                ) from exce

            if check_versions:
                self.versions = self.load_versions()

    @property
    def is_marketplace_app(self) -> bool:
        """
        This function checks if an plugin is available on the marketplace
        Function can be used as property

        Returns
        -------
            True: When the plugin was found on the marketplace (HTTP status 200)
            False: When the plugin wasn't found on the marketplace (HTTP status != 200)
        """

        try:
            resp = self.session.get(f"{API_URL}/addons/{self.key}", timeout=10)

            if resp.status_code == 200:
                return True

        except Exception as exce:  # pylint: disable=broad-exception-caught
            logging.warning(exce)
            return False

        return False

    def load_name(self) -> str:
        """
        A function returning the name of the plugin

        Returns
        -------
            name : str
                Name of the plugin
        """

        name = None

        if self.object:
            name = self.object["name"]

        return name

    def load_vendor(self) -> str:
        """
        A function returning the vendor of the plugin

        Returns
        -------
            vendor : str
                Vendor of the plugin
        """

        vendor = None

        if self.object:
            vendor = self.object["_embedded"]["vendor"]["name"]

        return vendor

    def check_version(self, version: str) -> int:
        """
        Checks how many versions are between the given version and the latest version on the marketplace
        """

        index = self.versions.index(version)
        diff = len(self.versions) - 1 - index

        return diff

    def _version_key(self, version: str) -> str:
        """
        Returning the version as main and subversion
        """

        parts = version.split(".")
        main_version = tuple(map(int, parts[:-1]))
        sub_version = int(parts[-1].split("-")[0])  # Ignore any suffix like 'jira7'

        return (main_version, sub_version)

    def load_versions(self) -> list:
        """
        Load plugin versions and returns them as a list

        Returns
        -------
            versions : list
                A list of versions for the plugin
        """
        versions = []

        next_ = True
        offset = 0

        while next_:
            resp = None
            try:
                resp = self.session.get(
                    f"{API_URL}/addons/{self.key}/versions?offset={offset}", timeout=10
                )
            except Exception as e:
                raise MarketplaceRequestException(
                    message=f"Request throw an exception {e}"
                ) from e

            if resp.status_code == 200:
                # i avoided checks, because the structure should not change
                jsobj = resp.json()
                vers = jsobj["_embedded"]["versions"]
                for version in vers:
                    name = version["name"]
                    if (
                        version["deployment"]["dataCenter"]
                        and version["deployment"].get("dataCenterStatus")
                        == "compatible"
                        and name not in versions
                    ):
                        versions.append(name)

                if jsobj["_links"].get("next"):
                    offset = jsobj["_links"]["next"]["href"].split("=")[-1]
                else:
                    next_ = False

        return versions
