"""
An exception module
"""


class MarketplaceRequestException(Exception):
    """
    Exception thrown if request to Atlassian marketplace failed
    """

    def __init__(self, message="Marketplace request failed", errors=None):
        super().__init__(message)
        self.errors = errors
