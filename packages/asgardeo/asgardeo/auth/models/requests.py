"""
OAuth2 request models
"""

from typing import Dict, Any, Optional
from pydantic import BaseModel


class TokenRequest(BaseModel):
    """Base token request model"""

    grant_type: str
    scope: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for HTTP request"""
        return {k: v for k, v in self.model_dump().items() if v is not None}


class ClientCredentialsRequest(TokenRequest):
    """Client credentials token request"""

    grant_type: str = "client_credentials"
    resource: Optional[str] = None
    audience: Optional[str] = None


class AuthorizationCodeRequest(TokenRequest):
    """Authorization code token request"""

    grant_type: str = "authorization_code"
    code: str
    redirect_uri: Optional[str] = None
    code_verifier: Optional[str] = None
    actor_token: Optional[str] = None


class RefreshTokenRequest(TokenRequest):
    """Refresh token request"""

    grant_type: str = "refresh_token"
    refresh_token: str

class AuthorizationRequest(BaseModel):
    """Authorization request for authorization code flow"""

    response_type: str = "code"
    client_id: str
    redirect_uri: Optional[str] = None
    scope: Optional[str] = None
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    resource: Optional[str] = None
    audience: Optional[str] = None

    def to_url_params(self) -> Dict[str, str]:
        """Convert to URL parameters"""
        params = {}
        for key, value in self.model_dump().items():
            if value is not None:
                params[key] = str(value)
        return params
