"""
This module represents the Atlassian Marketplace API in python

Author:     Mr128Bit
Created:    04/24

"""

import requests
import re
from bs4 import BeautifulSoup

from .Plugin import Plugin  # pylint: disable=cyclic-import

class MarketplaceAPI:  # pylint: disable=too-few-public-methods
    """
    A class representing the marketplace api from atlassian
    """

    def __init__(self):
        self.MARKETPLACE_URL = "https://marketplace.atlassian.com"

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

    def get_plugin_meta(self, marketplace_id):

        response = requests.get(f"{self.MARKETPLACE_URL}/apps/{marketplace_id}")

        app_type = None
        partner_name_text = None
        app_name_text = None
    
        if response.status_code == 200:
            # Inhalt der Webseite mit BeautifulSoup parsen
            soup = BeautifulSoup(response.content, 'html.parser')

            # Das gewünschte Element anhand seines Attributs finden
            element = soup.find('div', {'data-testid': 'app-header__compatibilities'})

            if element:
                # Textinhalt des Elements
                text = element.get_text()

                # Regulärer Ausdruck für "Jira" oder "Confluence" (ignore case)
                match = re.search(r'\b(jira|confluence)\b', text, re.IGNORECASE)

                if match:
                    # Der gefundene Begriff (ignoriert die Groß-/Kleinschreibung)
                    found_term = match.group(0).upper()
                    app_type = found_term
                
            partner_name_element = soup.find('span', class_='css-1rub5di-PartnerNameContainer-ellipsis emh330k3')
            if partner_name_element:
                partner_name_text = partner_name_element.text.strip()

            app_name_element = soup.find('h1', {'data-testid': 'app-header__app-name'})
            if app_name_element:
                app_name_text = app_name_element.text.strip()

        if app_type.lower() in ("confluence", "jira") and partner_name_text and app_name_text:
            return (app_type, partner_name_text, app_name_text)
        
        return None