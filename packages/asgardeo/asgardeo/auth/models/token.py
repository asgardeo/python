"""
OAuth2 token models
"""

import time
from enum import Enum
from typing import Optional
from pydantic import BaseModel


class OAuthTokenType(str, Enum):
    """OAuth2 token types"""

    CLIENT_CREDENTIALS = "client_credentials"
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"

class OAuthToken(BaseModel):
    """OAuth2 token response model"""

    access_token: str
    token_type: str = "Bearer"
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    scope: Optional[str] = None
    id_token: Optional[str] = None
    expires_at: Optional[float] = None

    def __init__(self, **data):
        super().__init__(**data)
        # Calculate expires_at if not provided
        if self.expires_in and not self.expires_at:
            self.expires_at = time.time() + self.expires_in

    def is_expired(self, buffer_seconds: int = 60) -> bool:
        """Check if token is expired with optional buffer"""
        if not self.expires_at:
            return False
        return time.time() >= (self.expires_at - buffer_seconds)

    def time_to_expiry(self) -> Optional[float]:
        """Get seconds until token expires"""
        if not self.expires_at:
            return None
        return max(0, self.expires_at - time.time())

    def is_valid(self) -> bool:
        """Check if token is valid (not expired)"""
        return not self.is_expired()

    def __str__(self) -> str:
        """String representation masking sensitive data"""
        masked_token = (
            f"{self.access_token[:8]}...{self.access_token[-4:]}"
            if len(self.access_token) > 12
            else "***"
        )
        return f"OAuthToken(access_token={masked_token}, token_type={self.token_type}, expires_in={self.expires_in})"
