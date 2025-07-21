"""
OAuth2 configuration models
"""

from typing import Optional
from pydantic import BaseModel, field_validator


class ClientConfig(BaseModel):
    """OAuth2 client configuration"""

    client_id: str
    client_secret: Optional[str] = None
    redirect_uri: Optional[str] = None

    @field_validator("client_id")
    @classmethod
    def validate_client_id(cls, v):
        if not v or not v.strip():
            raise ValueError("client_id cannot be empty")
        return v.strip()

    def __str__(self) -> str:
        """String representation masking sensitive data"""
        masked_secret = "***" if self.client_secret else None
        return f"ClientConfig(client_id={self.client_id}, client_secret={masked_secret}, redirect_uri={self.redirect_uri})"


class ServerConfig(BaseModel):
    """OAuth2 server configuration"""

    base_url: str
    token_endpoint: Optional[str] = None
    authorize_endpoint: Optional[str] = None

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, v):
        if not v or not v.strip():
            raise ValueError("base_url cannot be empty")
        # Ensure base_url doesn't end with /
        return v.strip().rstrip("/")

    def __init__(self, **data):
        super().__init__(**data)
        # Set default endpoints if not provided
        if not self.token_endpoint:
            self.token_endpoint = f"{self.base_url}/oauth2/token"
        if not self.authorize_endpoint:
            self.authorize_endpoint = f"{self.base_url}/oauth2/authorize"
