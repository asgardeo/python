"""
Asgardeo Auth Module - OAuth2 authentication functionality

This module provides OAuth2 flows, token management, and authentication utilities.
"""

from .token_client import TokenClient
from .token_manager import TokenManager
from .native_auth_client import NativeAuthClient

# Models
from .models.token import OAuthToken, OAuthTokenType
from .models.config import ClientConfig, ServerConfig
from .models.requests import (
    ClientCredentialsRequest,
    AuthorizationCodeRequest,
    RefreshTokenRequest,
    DeviceCodeRequest,
    DeviceAuthorizationRequest,
    AuthorizationRequest,
)
from .models.native_auth import (
    NativeAuthResponse,
    NativeAuthInitRequest,
    NativeAuthStepRequest,
    FlowStatus,
    StepType,
    AuthenticatorType,
    UsernamePasswordParams,
    TOTPParams,
    EmailOTPParams,
    SMSOTPParams,
)

# OAuth2 flows
from .flows.authorization_code import AuthorizationCodeFlow
from .flows.native_auth import NativeAuthFlow

# Storage
from .storage.memory_store import MemoryTokenStore
from .storage.file_store import FileTokenStore

# Interfaces
from .interfaces.token_store import TokenStore

# Exceptions
from .exceptions import (
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
)

# Utilities
from .utils.oauth import (
    generate_state,
    generate_pkce_pair,
    normalize_scope,
    build_authorization_url,
    extract_callback_params,
    validate_redirect_uri,
    encode_basic_auth,
)

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
    "ClientCredentialsRequest",
    "AuthorizationCodeRequest",
    "RefreshTokenRequest",
    "DeviceCodeRequest",
    "DeviceAuthorizationRequest",
    "AuthorizationRequest",
    # Native Auth Models
    "NativeAuthResponse",
    "NativeAuthInitRequest",
    "NativeAuthStepRequest",
    "FlowStatus",
    "StepType",
    "AuthenticatorType",
    "UsernamePasswordParams",
    "TOTPParams",
    "EmailOTPParams",
    "SMSOTPParams",
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
