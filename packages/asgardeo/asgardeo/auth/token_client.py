"""
OAuth2 token client for handling token requests
"""

import logging
from typing import Dict, Any, Optional
import httpx
from .models.token import OAuthToken
from .models.config import ClientConfig, ServerConfig
from .models.requests import TokenRequest
from .utils.oauth import encode_basic_auth
from .exceptions import (
    TokenExpiredError,
    AuthenticationError,
    NetworkError,
)

logger = logging.getLogger(__name__)


class TokenClient:
    """OAuth2 token client for handling all token requests"""

    def __init__(self, client_config: ClientConfig, server_config: ServerConfig):
        self.client_config = client_config
        self.server_config = server_config

    async def request_token(self, token_request: TokenRequest) -> OAuthToken:
        """
        Request OAuth2 token using any grant type

        Args:
            token_request: Token request with grant_type and parameters

        Returns:
            OAuth2 token

        Raises:
            AuthenticationError: If token request fails
        """
        try:
            logger.debug(
                f"Requesting token with grant_type: {token_request.grant_type}"
            )

            # Prepare request data
            data = token_request.to_dict()

            # Prepare headers
            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            # Add client authentication
            if self.client_config.client_secret:
                # Use Basic authentication
                headers["Authorization"] = encode_basic_auth(
                    self.client_config.client_id, self.client_config.client_secret
                )
            else:
                # Use client_id in body for public clients
                data["client_id"] = self.client_config.client_id

            # Make token request
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.server_config.token_endpoint, data=data, headers=headers
                )

                if response.status_code != 200:
                    error_data = {}
                    try:
                        error_data = response.json()
                    except:
                        pass

                    error_code = error_data.get("error", "unknown_error")
                    error_description = error_data.get(
                        "error_description", response.text
                    )

                    logger.error(
                        f"Token request failed: {error_code} - {error_description}"
                    )
                    raise AuthenticationError(
                        f"Token request failed: {error_code} - {error_description}",
                        error_code=error_code,
                        error_description=error_description,
                    )

                token_data = response.json()
                token = OAuthToken(**token_data)

                logger.debug(
                    f"Successfully obtained token with grant_type: {token_request.grant_type}"
                )
                return token

        except AuthenticationError:
            raise
        except httpx.HTTPError as e:
            logger.error(f"Network error during token request: {e}")
            raise NetworkError(f"Network error during token request: {e}")
        except Exception as e:
            logger.error(f"Token request failed: {e}")
            raise AuthenticationError(f"Token request failed: {e}")

    async def refresh_token(
        self, refresh_token: str, scopes: Optional[str] = None
    ) -> OAuthToken:
        """
        Refresh OAuth2 token

        Args:
            refresh_token: Refresh token
            scopes: Optional scopes string

        Returns:
            New OAuth2 token

        Raises:
            TokenExpiredError: If refresh fails
        """
        try:
            from .models.requests import RefreshTokenRequest

            request = RefreshTokenRequest(refresh_token=refresh_token, scope=scopes)

            return await self.request_token(request)

        except AuthenticationError as e:
            logger.error(f"Token refresh failed: {e}")
            raise TokenExpiredError(f"Token refresh failed: {e}")

    async def revoke_token(
        self, token: str, token_type_hint: str = "access_token"
    ) -> bool:
        """
        Revoke OAuth2 token

        Args:
            token: Token to revoke
            token_type_hint: Type of token (access_token or refresh_token)

        Returns:
            True if revocation was successful
        """
        try:
            revoke_endpoint = f"{self.server_config.base_url}/oauth2/revoke"

            data = {
                "token": token,
                "token_type_hint": token_type_hint,
            }

            headers = {"Content-Type": "application/x-www-form-urlencoded"}

            # Add client authentication
            if self.client_config.client_secret:
                headers["Authorization"] = encode_basic_auth(
                    self.client_config.client_id, self.client_config.client_secret
                )
            else:
                data["client_id"] = self.client_config.client_id

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    revoke_endpoint, data=data, headers=headers
                )
                return response.status_code == 200

        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False

    async def close(self):
        """Close the token client"""
        pass  # No resources to close in this implementation
