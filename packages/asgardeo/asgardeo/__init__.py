"""
Asgardeo SDK - OAuth2 authentication and identity management

This package provides OAuth2 authentication capabilities for applications.
"""

from .auth import (
    # Core OAuth2 components
    TokenClient,
    TokenManager,
    NativeAuthClient,
    # Models
    OAuthToken,
    OAuthTokenType,
    ClientConfig,
    ServerConfig,
    # OAuth2 flows
    AuthorizationCodeFlow,
    NativeAuthFlow,
    # Storage
    MemoryTokenStore,
    FileTokenStore,
    TokenStore,
    # Exceptions
    OAuthError,
    TokenExpiredError,
    AuthenticationError,
    InvalidTokenError,
    InvalidGrantError,
    InvalidClientError,
    InvalidScopeError,
    AuthorizationError,
    NetworkError,
    ConfigurationError,
    # Utilities
    generate_state,
    generate_pkce_pair,
    normalize_scope,
    build_authorization_url,
    extract_callback_params,
    validate_redirect_uri,
    encode_basic_auth,
)

__version__ = "1.0.0"
__title__ = "Asgardeo SDK"
__description__ = "OAuth2 authentication and identity management"
__author__ = "WSO2"
__license__ = "Apache-2.0"

__all__ = [
    # Core components
    "TokenClient",
    "TokenManager",
    "NativeAuthClient",
    # Models
    "OAuthToken",
    "OAuthTokenType",
    "ClientConfig",
    "ServerConfig",
    # OAuth2 flows
    "AuthorizationCodeFlow",
    "NativeAuthFlow",
    # Storage
    "MemoryTokenStore",
    "FileTokenStore",
    "TokenStore",
    # Exceptions
    "OAuthError",
    "TokenExpiredError",
    "AuthenticationError",
    "InvalidTokenError",
    "InvalidGrantError",
    "InvalidClientError",
    "InvalidScopeError",
    "AuthorizationError",
    "NetworkError",
    "ConfigurationError",
    # Utilities
    "generate_state",
    "generate_pkce_pair",
    "normalize_scope",
    "build_authorization_url",
    "extract_callback_params",
    "validate_redirect_uri",
    "encode_basic_auth",
]
