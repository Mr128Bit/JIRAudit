"""
This module represents the Atlassian Marketplace API in python

Author:     Mr128Bit
Created:    04/24

"""

from .Plugin import Plugin  # pylint: disable=cyclic-import


class MarketplaceAPI:  # pylint: disable=too-few-public-methods
    """
    A class representing the marketplace api from atlassian
    """

    def __init__(self):
        pass

    def get_plugin_by_key(self, key: str) -> Plugin:
        """
        This plugins returns a plugin by key

        Parameters
        ----------
            key : str
                The atlassian plugin key

        Returns
        -------
            plugin : Plugin
                A Plugin object representing the marketplace plugin
        """
        plugin = Plugin(key)
        plugin.load_versions()

        return plugin
