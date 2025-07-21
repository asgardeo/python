"""
OAuth2 exceptions for Asgardeo authentication
"""


class OAuthError(Exception):
    """Base OAuth2 error"""

    def __init__(
        self, message: str, error_code: str = None, error_description: str = None
    ):
        super().__init__(message)
        self.error_code = error_code
        self.error_description = error_description


class TokenExpiredError(OAuthError):
    """Token has expired"""

    pass


class AuthenticationError(OAuthError):
    """Authentication failed"""

    pass


class InvalidTokenError(OAuthError):
    """Invalid token provided"""

    pass


class InvalidGrantError(OAuthError):
    """Invalid grant type or grant parameters"""

    pass


class InvalidClientError(OAuthError):
    """Invalid client credentials"""

    pass


class InvalidScopeError(OAuthError):
    """Invalid or unauthorized scope"""

    pass


class AuthorizationError(OAuthError):
    """Authorization failed"""

    pass


class NetworkError(OAuthError):
    """Network-related error"""

    pass


class ConfigurationError(OAuthError):
    """Configuration error"""

    pass
