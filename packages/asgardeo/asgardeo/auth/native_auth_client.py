"""
App Native Authentication API client implementation
"""

import logging
from typing import Dict, Any, Optional, List
import httpx
from .models.config import ClientConfig, ServerConfig
from .models.native_auth import (
    NativeAuthInitRequest,
    NativeAuthResponse,
    NativeAuthStepRequest,
    SelectedAuthenticator,
    FlowStatus,
    UsernamePasswordParams,
    TOTPParams,
    EmailOTPParams,
    SMSOTPParams,
)
from .utils.oauth import generate_state, generate_pkce_pair
from .exceptions import AuthenticationError, NetworkError

logger = logging.getLogger(__name__)


class NativeAuthClient:
    """App Native Authentication API client"""

    def __init__(self, client_config: ClientConfig, server_config: ServerConfig):
        self.client_config = client_config
        self.server_config = server_config

        # Set native auth endpoints
        self.authorize_endpoint = f"{server_config.base_url}/oauth2/authorize"
        self.authn_endpoint = f"{server_config.base_url}/oauth2/authn"

        # PKCE state
        self.code_verifier: Optional[str] = None
        self.code_challenge: Optional[str] = None

    async def initiate_authentication(
        self,
        scopes: List[str],
        redirect_uri: Optional[str] = None,
        state: Optional[str] = None,
    ) -> NativeAuthResponse:
        """
        Initiate native authentication flow

        Args:
            scopes: List of OAuth2 scopes
            redirect_uri: Redirect URI (uses client config if not provided)
            state: State parameter (auto-generated if not provided)

        Returns:
            Native authentication response

        Raises:
            AuthenticationError: If initiation fails
        """
        try:
            if not state:
                state = generate_state()

            # Generate PKCE pair
            self.code_verifier, self.code_challenge = generate_pkce_pair()

            request = NativeAuthInitRequest(
                client_id=self.client_config.client_id,
                redirect_uri=redirect_uri or self.client_config.redirect_uri,
                scope=" ".join(scopes) if scopes else None,
                state=state,
                code_challenge=self.code_challenge,
                code_challenge_method="S256",
            )

            logger.debug(
                f"Initiating native authentication for client: {self.client_config.client_id}"
            )

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.authorize_endpoint,
                    data=request.to_url_params(),
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                )

                if response.status_code != 200:
                    error_text = response.text
                    logger.error(f"Native auth initiation failed: {error_text}")
                    raise AuthenticationError(
                        f"Native auth initiation failed: {error_text}"
                    )

                response_data = response.json()
                auth_response = NativeAuthResponse(**response_data)

                logger.debug(
                    f"Native auth initiated successfully, flow_id: {auth_response.flow_id}"
                )
                return auth_response

        except httpx.HTTPError as e:
            logger.error(f"Network error during native auth initiation: {e}")
            raise NetworkError(f"Network error during native auth initiation: {e}")
        except Exception as e:
            logger.error(f"Native auth initiation failed: {e}")
            raise AuthenticationError(f"Native auth initiation failed: {e}")

    async def authenticate_with_username_password(
        self, flow_id: str, authenticator_id: str, username: str, password: str
    ) -> NativeAuthResponse:
        """
        Authenticate using username and password

        Args:
            flow_id: Flow ID from initiation
            authenticator_id: Username/password authenticator ID
            username: Username
            password: Password

        Returns:
            Native authentication response
        """
        params = UsernamePasswordParams(username=username, password=password)

        return await self._perform_authentication_step(
            flow_id=flow_id, authenticator_id=authenticator_id, params=params
        )

    async def authenticate_with_totp(
        self, flow_id: str, authenticator_id: str, totp_token: str
    ) -> NativeAuthResponse:
        """
        Authenticate using TOTP token

        Args:
            flow_id: Flow ID from previous step
            authenticator_id: TOTP authenticator ID
            totp_token: TOTP token

        Returns:
            Native authentication response
        """
        params = TOTPParams(token=totp_token)

        return await self._perform_authentication_step(
            flow_id=flow_id, authenticator_id=authenticator_id, params=params
        )

    async def authenticate_with_email_otp(
        self, flow_id: str, authenticator_id: str, otp_code: str
    ) -> NativeAuthResponse:
        """
        Authenticate using Email OTP

        Args:
            flow_id: Flow ID from previous step
            authenticator_id: Email OTP authenticator ID
            otp_code: OTP code

        Returns:
            Native authentication response
        """
        params = EmailOTPParams(otpCode=otp_code)

        return await self._perform_authentication_step(
            flow_id=flow_id, authenticator_id=authenticator_id, params=params
        )

    async def authenticate_with_sms_otp(
        self, flow_id: str, authenticator_id: str, otp_code: str
    ) -> NativeAuthResponse:
        """
        Authenticate using SMS OTP

        Args:
            flow_id: Flow ID from previous step
            authenticator_id: SMS OTP authenticator ID
            otp_code: OTP code

        Returns:
            Native authentication response
        """
        params = SMSOTPParams(otpCode=otp_code)

        return await self._perform_authentication_step(
            flow_id=flow_id, authenticator_id=authenticator_id, params=params
        )

    async def authenticate_with_custom_params(
        self, flow_id: str, authenticator_id: str, params: Dict[str, Any]
    ) -> NativeAuthResponse:
        """
        Authenticate using custom parameters

        Args:
            flow_id: Flow ID from previous step
            authenticator_id: Authenticator ID
            params: Custom authentication parameters

        Returns:
            Native authentication response
        """
        return await self._perform_authentication_step(
            flow_id=flow_id, authenticator_id=authenticator_id, params=params
        )

    async def _perform_authentication_step(
        self, flow_id: str, authenticator_id: str, params: Any
    ) -> NativeAuthResponse:
        """
        Perform an authentication step

        Args:
            flow_id: Flow ID
            authenticator_id: Authenticator ID
            params: Authentication parameters

        Returns:
            Native authentication response

        Raises:
            AuthenticationError: If authentication step fails
        """
        try:
            selected_authenticator = SelectedAuthenticator(
                authenticator_id=authenticator_id, params=params
            )

            request = NativeAuthStepRequest(
                flow_id=flow_id, selected_authenticator=selected_authenticator
            )

            logger.debug(f"Performing authentication step for flow: {flow_id}")

            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.authn_endpoint,
                    json=request.to_dict(),
                    headers={"Content-Type": "application/json"},
                )

                if response.status_code != 200:
                    error_text = response.text
                    logger.error(f"Authentication step failed: {error_text}")
                    raise AuthenticationError(
                        f"Authentication step failed: {error_text}"
                    )

                response_data = response.json()
                auth_response = NativeAuthResponse(**response_data)

                logger.debug(
                    f"Authentication step completed, status: {auth_response.flow_status}"
                )
                return auth_response

        except httpx.HTTPError as e:
            logger.error(f"Network error during authentication step: {e}")
            raise NetworkError(f"Network error during authentication step: {e}")
        except Exception as e:
            logger.error(f"Authentication step failed: {e}")
            raise AuthenticationError(f"Authentication step failed: {e}")

    def is_authentication_complete(self, response: NativeAuthResponse) -> bool:
        """
        Check if authentication is complete

        Args:
            response: Native authentication response

        Returns:
            True if authentication is complete
        """
        return response.flow_status == FlowStatus.SUCCESS_COMPLETED

    def has_authentication_failed(self, response: NativeAuthResponse) -> bool:
        """
        Check if authentication has failed

        Args:
            response: Native authentication response

        Returns:
            True if authentication has failed
        """
        return response.flow_status == FlowStatus.FAIL_INCOMPLETE

    def get_authorization_code(self, response: NativeAuthResponse) -> Optional[str]:
        """
        Extract authorization code from completed authentication

        Args:
            response: Native authentication response

        Returns:
            Authorization code or None if not available
        """
        if self.is_authentication_complete(response) and response.auth_data:
            return response.auth_data.code
        return None

    def get_code_verifier(self) -> Optional[str]:
        """
        Get the PKCE code verifier for token exchange

        Returns:
            PKCE code verifier or None if not available
        """
        return self.code_verifier

    def get_available_authenticators(
        self, response: NativeAuthResponse
    ) -> List[Dict[str, Any]]:
        """
        Get available authenticators from response

        Args:
            response: Native authentication response

        Returns:
            List of available authenticators
        """
        if response.next_step and response.next_step.authenticators:
            return [
                {
                    "id": auth.authenticator_id,
                    "type": auth.authenticator,
                    "idp": auth.idp,
                    "required_params": auth.required_params or [],
                    "metadata": auth.metadata or {},
                }
                for auth in response.next_step.authenticators
            ]
        return []

    def find_authenticator_by_type(
        self, response: NativeAuthResponse, authenticator_type: str
    ) -> Optional[Dict[str, Any]]:
        """
        Find authenticator by type

        Args:
            response: Native authentication response
            authenticator_type: Type of authenticator to find

        Returns:
            Authenticator info or None if not found
        """
        authenticators = self.get_available_authenticators(response)
        for auth in authenticators:
            if auth["type"] == authenticator_type:
                return auth
        return None

    async def close(self):
        """Close the native auth client"""
        pass  # No resources to close in this implementation
