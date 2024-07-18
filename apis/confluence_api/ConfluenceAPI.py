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
import base64
import requests
from lxml import etree
import urllib3
from requests.adapters import HTTPAdapter, Retry
from ..exceptions import api_exceptions

from ..template import API
from ..enums import endpoints

logger = logging.getLogger(__name__)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class ConfluenceAPI(API.API):

    def __init__(self, base_url: str, username: str = None, password: str = None, verify_ssl=True):
        super().__init__(base_url=base_url, username=username, password=password, verify_ssl=verify_ssl)
        print(verify_ssl)


    def websudo_request(self, url: str) -> requests.models.Response:

        header = {
            "Authorization": f"Basic {self.BASIC_AUTH}"
        }


        try:
            response = self.SESSION.get(f"{self.BASE_URL}{url}?os_authType=basic", headers=header, verify=self.VERIFY_SSL)

            response.raise_for_status()

            status_code = response.status_code

            if status_code != 200:
                raise api_exceptions.APIRequestException(
                    message=f"Request resulted in HTTP status {status_code}"
                )

        except Exception as e:
            raise api_exceptions.APIRequestException(message=f"Request threw an exception {e}") from e

        return response
    
    def init_auth(self) -> bool:
        auth_string = f"{self.USERNAME}:{self.PASSWORD}"

        if self.USERNAME and self.PASSWORD:

            auth_encoded = base64.b64encode(auth_string.encode()).decode()
            self.BASIC_AUTH = auth_encoded
        try:
            if not self.authenticated:
                response = self.websudo_request("/")
                if response.status_code == 200:

                    self._AUTHENTICATED = True
                    return True
            else:
                return True
        except:  # pylint: disable=bare-except
            return False
