from ..template import API

class AuthenticationFailedException(Exception):
    """
    Exception thrown if authentication with api failed
    """

    def __init__(self, message="Authentication for user failed", errors=None):
        super().__init__(message)
        self.errors = errors


class APIRequestException(Exception):
    """
    Exception thrown if a request to instance failed with any reason
    """

    def __init__(self, message="API request failed", errors=None):
        super().__init__(message)
        self.errors = errors