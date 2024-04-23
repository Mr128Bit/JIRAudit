from pathlib import Path

import requests
from lxml import etree
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class PluginManager:

    def __init__(self, base_url, config: dict, silent_mode=False):
        self.PLUGINS_CONFIG = config
        self.BASE_URL = base_url
        self.SILENT_MODE = silent_mode

    class PluginEnumerationException(Exception):
        def __init__(
            self, message="Plugin enumeration failed (request error)", errors=None
        ):
            super().__init__(message)
            self.errors = errors

    class PluginImportException(Exception):
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

    def enum_plugins_unauthenticated(self) -> list:
        """
        Enumerates all plugins, but unauthenticated
        # TODO: code überarbeiten, exception handling überarbeiten
        """

        def update_status(status):
            self._print_msg(status, end="\r")

        endpoints = self.PLUGINS_CONFIG["plugin_detection"]["endpoints"]
        s_endpoints = [v for x, v in endpoints.items() if v.get("urls")]
        count = len(s_endpoints)
        plugins_found = []

        try:
            self._print_msg("\n\033[97m", "_" * 20, "[Plugin-Enum]", "_" * 20, "\033[00m\n")
            self._print_msg(
                "\n\033[93mI will now try to enumerate the plugins without being authenticated...\033[00m\n"
            )

            i = 0
            for plugin, meta in endpoints.items():
                if meta.get("urls"):
                    i += 1

                name = meta.get("name")
                vendor = meta.get("vendor")
                marketplace_url = meta.get("marketplace_url")

                for url in meta.get("urls"):
                    try:
                        req_url = f"{self.BASE_URL}{url}"
                        response = requests.get(req_url, timeout=10)

                        if response.status_code == 200:
                            current_url = response.url

                            if (
                                "/download/resources/" in current_url
                                or "permissionViolation" in current_url
                                or "aui-message-warning" in response.text
                                or "login-form-username" not in response.text
                            ):
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
            raise

        self._print_msg("\n\033[91m", "_" * 55, "\033[00m\n")

        return plugins_found
