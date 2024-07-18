"""
This module is used for managing and enumerating atlassian jira marketplace plugins

Author:     Mr128Bit
Created:    04/24


"""

import requests
import urllib3
import os
import zipfile
import glob
import re
import json
from pathlib import Path
from bs4 import BeautifulSoup
from misc.Types import AppType
from settings import CONFLUENCE_PLUGINS_CONFIG_PATH, JIRA_PLUGINS_CONFIG_PATH, VERIFY_SSL
from apis.marketplace_api.MarketplaceAPI import MarketplaceAPI

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginManager:
    """
    This is the plugin manager class for managing marketplace plugins

    TODO: Add import for plugins
    """
    def __init__(self, base_url, jira_config: dict, confluence_config: dict, app_type: AppType, excluded_endpoints: list=[], silent_mode=False):
        self.JIRA_PLUGINS_CONFIG = jira_config
        self.CONFLUENCE_PLUGINS_CONFIG = confluence_config
        self.BASE_URL = base_url
        self.SILENT_MODE = silent_mode
        self.EXCLUDED_ENDPOINTS = excluded_endpoints
        self.APP_TYPE = app_type

    class PluginEnumerationException(Exception):
        """
        This exception is thrown when an error occured while enumerating plugins
        """
        def __init__(
            self, message="Plugin enumeration failed (request error)", errors=None
        ):
            super().__init__(message)
            self.errors = errors

    class PluginImportException(Exception):
        """
        This exception is thrown when an error occured while importing plugins (currently unused)
        """
        def __init__(self, message="Plugin import failed (request error)", errors=None):
            super().__init__(message)
            self.errors = errors

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
        self, name: str, version: str = None, vendor: str = None, url: str = None
    ):
        """
        Prints a found plugin

            Parameters:
                name (str):     Name of the plugin
                version (str):  Version of the plugin
                vendor (str):   Name of the plugin's vendor
        """
        if name and vendor and url:
            self._print_msg(
                    f"\n\033[96m[PLUGIN]\033[00m {name}\nVersion: \033[92m{version}\033[00m\nVendor: {vendor}"
                )
            self._print_msg(url)

        else:
            self._print_msg(
                f"\n\033[96m[PLUGIN]\033[00m {name}\nVersion: \033[91mUnknown\033[00m\nVendor: \033[91mUnknown\033[00m"
            )

    def _download_file(self, url, folder):
        # Dateiname aus der URL extrahieren
        local_filename = os.path.join(folder, url.split('/')[-1])
        
        # Datei herunterladen und speichern
        with requests.get(url, stream=True) as r:
            r.raise_for_status()
            with open(local_filename, 'wb') as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        
        return local_filename

    def _unzip_file(self, file, location):
        # Sicherstellen, dass der Zielordner existiert
        if not os.path.exists(location):
            os.makedirs(location)

        # ZIP-Datei entpacken
        with zipfile.ZipFile(file, 'r') as zip_ref:
            zip_ref.extractall(location)

    def _find_jar_files(self, directory):
        # Verwenden von glob, um alle .jar-Dateien im Verzeichnis (nicht rekursiv) zu finden
        jar_files = glob.glob(os.path.join(directory, '*.jar'))
        return jar_files
    
    def _find_urls(self, directory):
        xml_file = glob.glob(os.path.join(directory, 'atlassian-plugin.xml'))
        urls = []
        ignore = ["com.atlassian.confluence.plugins"]

        if xml_file:
            xml_file = xml_file[0]
            try:
                with open(xml_file, 'r', encoding='utf-8') as f:
                    xml_content = f.read()
                    
                    patterns = None

                    if self.APP_TYPE == AppType.JIRA:
                        patterns = [
                            # TODO: Add end at ',
                            r'/secure/[^<#\?"\]]*',  # Muster endet vor <, #, ?, " oder ]
                            r'/plugins/[^<#\?"\]]*'  # Muster endet vor <, #, ?, " oder ]
                        ]
                    else:
                        patterns = [
                            r'/download/resources/[^<#\?"\]]*'
                        ]              
                    # Suche nach den Mustern in der XML-Datei
                    for pattern in patterns:
                        
                        matches = re.findall(pattern, xml_content)
                        
                        if matches:
                            
                            for match in [m for m in matches if match not in self.EXCLUDED_ENDPOINTS]:
                                # if strings in ignore list not found in match append
                                if not [im for im in ignore if im in match]:
                                    urls.append(match)
            except FileNotFoundError:
                print(f"Die Datei '{xml_file}' wurde nicht gefunden.")
            except Exception as e:
                print(f"Fehler beim Lesen der Datei '{xml_file}': {e}")
        return urls

    def _clean(self, directory):
        if os.path.isdir(directory):

            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)

                if os.path.isdir(item_path):
                    self._clean(item_path)
                    os.rmdir(item_path)

                elif os.path.isfile(item_path):
                    os.remove(item_path)


    def _update_config(self, app_type: AppType):
        
        path = None
        config = None
        if app_type == AppType.CONFLUENCE:
            config = self.CONFLUENCE_PLUGINS_CONFIG
            path = CONFLUENCE_PLUGINS_CONFIG_PATH
        else:
            path = JIRA_PLUGINS_CONFIG_PATH
            config = self.JIRA_PLUGINS_CONFIG

        with open(path, "w", encoding="UTF-8") as f:
            json.dump(config, f, indent=4, ensure_ascii=False)

    def import_plugin(self, marketplace_id):

        folder = os.path.dirname(os.path.abspath(__file__))
        folder = Path(folder) / "plugins" / "import"
        url = f"https://marketplace.atlassian.com/download/apps/{marketplace_id}"

        market_api = MarketplaceAPI()
        meta = market_api.get_plugin_meta(marketplace_id)

        if meta:
            app_type = meta[0]
            vendor = meta[1]
            name = meta[2]

            filen = self._download_file(url, folder)

            self._unzip_file(filen, folder)

            # delete og file
            if os.path.exists(filen):
                os.remove(filen)

            jars = self._find_jar_files(folder)

            for jar in jars:
                self._unzip_file(jar, folder)
            
            urls = self._find_urls(folder)

            print("Plugin:", name)
            print("Platform:", app_type.value)
            print("Vendor:", vendor)
            print("Found urls:", urls)

            self._clean(folder)

            entry = {
                "name": name,
                "vendor": vendor,   
                "marketplace_url": f"https://marketplace.atlassian.com/apps/{marketplace_id}",
                "urls": urls
            }

            if app_type == AppType.CONFLUENCE:
                self.CONFLUENCE_PLUGINS_CONFIG["plugin_detection"]["endpoints"][marketplace_id] = entry
            elif app_type == AppType.JIRA:
                self.JIRA_PLUGINS_CONFIG["plugin_detection"]["endpoints"][marketplace_id] = entry

        self._update_config(app_type)


    def enum_plugins_unauthenticated(self) -> list: # pylint: disable=too-many-locals
        """
        Enumerates all plugins, but unauthenticated
        # TODO: code überarbeiten, exception handling überarbeiten
        """

        def update_status(status):
            self._print_msg(status, end="\r")
        
        endpoints = None
        if self.APP_TYPE == AppType.JIRA:
            endpoints = self.JIRA_PLUGINS_CONFIG["plugin_detection"]["endpoints"]
        else:
            endpoints = self.CONFLUENCE_PLUGINS_CONFIG["plugin_detection"]["endpoints"]

        s_endpoints = [v for x, v in endpoints.items() if v.get("urls")]
        count = len(s_endpoints)
        plugins_found = []
        # this is messy i know, i'll change later
        try: # pylint: disable=too-many-nested-blocks
            self._print_msg("\n\033[97m", "_" * 20, "[Plugin-Enum]", "_" * 20, "\033[00m\n")
            self._print_msg(
                "\n\033[93mI will now try to enumerate the plugins without being authenticated...\033[00m\n"
            )

            i = 0
            for plugin, meta in endpoints.items(): # pylint: disable=unused-variable
                if meta.get("urls"):
                    i += 1

                name = meta.get("name")
                vendor = meta.get("vendor")
                marketplace_url = meta.get("marketplace_url")

                for url in meta.get("urls"):
                    try:
                        req_url = f"{self.BASE_URL}{url}"
                        response = requests.get(req_url, timeout=10, verify=VERIFY_SSL)

                        if response.status_code == 200:
                            current_url = response.url

                            if self.APP_TYPE == AppType.CONFLUENCE:
                                if not ("/download/resources/" in current_url and current_url == req_url):
                                    continue
                            if self.APP_TYPE == AppType.JIRA: 
                                if not (
                                    ("/download/resources/" in current_url and current_url == req_url)
                                    or "permissionViolation" in current_url
                                    or "aui-message-warning" in response.text
                                    or "login-form-username" not in response.text
                                ):
                                    continue
                            
                            self.print_plugin_found(
                                name, vendor=vendor, url=marketplace_url
                            )
                            plugins_found.append(
                                {
                                    "name": name,
                                    "vendor": vendor,
                                    "url": marketplace_url,
                                }
                            )
                            break
                    except Exception as exc:
                        raise self.PluginEnumerationException from exc

                update_status(f"Scanned {i} / {count} plugins")

        except Exception as e:
            raise self.PluginEnumerationException from e

        self._print_msg("\n\033[91m", "_" * 55, "\033[00m\n")

        return plugins_found
