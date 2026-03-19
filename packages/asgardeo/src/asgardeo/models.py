"""
Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
WSO2 LLC. licenses this file to you under the Apache License,
Version 2.0 (the "License"); you may not use this file except
in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
"""

"""Data models for Asgardeo SDK."""

from dataclasses import dataclass


class AsgardeoError(Exception):
    """Base exception class for Asgardeo SDK errors."""


class AuthenticationError(AsgardeoError):
    """Raised when authentication fails."""


class TokenError(AsgardeoError):
    """Raised when token operations fail."""


class NetworkError(AsgardeoError):
    """Raised when network requests fail."""


class ValidationError(AsgardeoError):
    """Raised when input validation fails."""


@dataclass
class AsgardeoConfig:
    """Configuration for Asgardeo clients."""

    base_url: str
    client_id: str
    redirect_uri: str
    client_secret: str | None = None
    scope: str = "openid internal_login"


@dataclass
class OAuthToken:
    """OAuth token response."""

    access_token: str
    id_token: str | None = None
    refresh_token: str | None = None
    expires_in: int | None = None
    token_type: str = "Bearer"
    scope: str | None = None


@dataclass
class CIBAResponse:
    """CIBA backchannel authentication response."""

    auth_req_id: str
    interval: int = 2
    expires_in: int = 120
    auth_url: str | None = None


class FlowStatus:
    """Authentication flow status constants."""

    SUCCESS_COMPLETED = "SUCCESS_COMPLETED"
    INCOMPLETE = "INCOMPLETE"


class CIBAStatus:
    """CIBA polling status constants."""

    AUTHORIZATION_PENDING = "authorization_pending"
    SLOW_DOWN = "slow_down"
    EXPIRED_TOKEN = "expired_token"
    ACCESS_DENIED = "access_denied"


class CIBAAuthenticationError(AuthenticationError):
    """Raised when CIBA authentication fails (expired, denied, etc.)."""
