from enum import Enum 

class CONFLUENCE_WEB_ENDPOINTS(Enum):
    """
    An enum class listing all used confluence web endpoints in this api
    This endpoints are used, when no API endpoint is available    
    """

    LOGIN = "/login.jsp"

class CONFLUENCE_API_ENDPOINTS(Enum):
    """
    An enum class listing all used official jira api endpoints in this api
    """

    SERVERINFO = "/rest/api/latest/serverInfo"
    PLUGIN_INFO = "/rest/plugins/1.0/"
    SEARCH_USER = "/rest/api/2/user/search"
    MYSELF = "/rest/api/latest/myself"
    AUTH = "/rest/auth/1/session"
    DASHBOARDS = "/rest/api/2/dashboard?maxResults=100"