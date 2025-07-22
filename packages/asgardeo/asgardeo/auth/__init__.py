"""
Asgardeo Auth Module - OAuth2 authentication functionality

This module provides OAuth2 flows, token management, and authentication utilities.
"""

from .token_client import TokenClient
from .native_auth_client import NativeAuthClient

# Models
from .models.token import OAuthToken, OAuthTokenType
from .models.config import ClientConfig, ServerConfig
from .models.requests import (
    ClientCredentialsRequest,
    AuthorizationCodeRequest,
    RefreshTokenRequest,
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
    "NativeAuthClient",
    # Models
    "OAuthToken",
    "OAuthTokenType",
    "ClientConfig",
    "ServerConfig",
    "ClientCredentialsRequest",
    "AuthorizationCodeRequest",
    "RefreshTokenRequest",
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
