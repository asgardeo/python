"""
Agent-enhanced OAuth2 authentication manager
"""

import logging
from typing import Dict, List, Optional, Tuple, Any

from asgardeo.auth.utils.oauth import build_authorization_url, generate_pkce_pair

from asgardeo.auth import (
    TokenClient,
    NativeAuthClient,
    ClientConfig,
    ServerConfig,
    OAuthToken,
    AuthorizationCodeRequest,
    FlowStatus,
    generate_state,
)
from .models import AgentConfig
from .exceptions import AIAuthenticationError, AgentAuthenticationError

logger = logging.getLogger(__name__)


class AgentAuthManager:
    """Agent-enhanced OAuth2 authentication manager"""

    def __init__(
        self,
        client_config: ClientConfig,
        server_config: ServerConfig,
        agent_config: Optional[AgentConfig] = None,
        authorization_timeout: int = 300,
    ):
        self.client_config = client_config
        self.server_config = server_config
        self.agent_config = agent_config
        self.authorization_timeout = authorization_timeout

        # Initialize clients
        self.token_client = TokenClient(client_config, server_config)
        self.native_client = NativeAuthClient(client_config, server_config)

    async def get_agent_token(self, scopes: List[str]) -> OAuthToken:
        """
        Get token for AI agent using native authentication with TOTP

        Args:
            scopes: List of OAuth2 scopes

        Returns:
            OAuth2 token for the agent

        Raises:
            AgentAuthenticationError: If agent authentication fails
        """
        if not self.agent_config:
            raise AgentAuthenticationError(
                "Agent configuration is required for agent authentication"
            )

        try:
            logger.debug(
                f"Getting agent token for agent: {self.agent_config.agent_name}"
            )

            # Use native authentication flow for agent
            init_response = await self.native_client.initiate_authentication(
                scopes=scopes
            )

            if init_response.flow_status == FlowStatus.SUCCESS_COMPLETED:
                logger.info(
                    f"Agent {self.agent_config.agent_name} authentication completed successfully"
                )
                auth_data = init_response.auth_data
                pass
            elif init_response.flow_status == FlowStatus.INCOMPLETE:
                username_auth = self.native_client.find_authenticator_by_type(
                    init_response, "Username & Password"
                )
                auth_response = (
                    await self.native_client.authenticate_with_username_password(
                        flow_id=init_response.flow_id,
                        authenticator_id=username_auth["id"],
                        username=self.agent_config.agent_id,
                        password=self.agent_config.agent_secret,
                    )
                )
                if auth_response.flow_status == FlowStatus.SUCCESS_COMPLETED:
                    logger.info(
                        f"Agent {self.agent_config.agent_name} authentication completed successfully"
                    )
                    auth_data = auth_response.auth_data
                else:
                    raise AgentAuthenticationError(
                        f"Agent authentication failed with status: {auth_response.flow_status}"
                    )
            else:
                raise AgentAuthenticationError(
                    f"Unexpected flow status: {init_response.flow_status}"
                )

            auth_code = auth_data.code
            code_verifier = self.native_client.get_code_verifier()
            if auth_code:
                print(f"   Authorization Code: {auth_code[:10]}...")
                print(f"   Code Verifier Available: {'Yes' if code_verifier else 'No'}")
                token_request = AuthorizationCodeRequest(
                    code=auth_code,
                    redirect_uri=self.native_client.client_config.redirect_uri,
                    code_verifier=code_verifier,
                )
                return await self.token_client.request_token(token_request)
            else:
                raise AgentAuthenticationError(
                    "No authorization code received during agent authentication"
                )
        except Exception as e:
            logger.error(f"Agent authentication failed: {e}")
            raise AgentAuthenticationError(f"Agent authentication failed: {e}")

    def get_authorization_url_with_pkce(
        self,
        scopes: List[str],
        state: Optional[str] = None,
        resource: Optional[str] = None,
        **kwargs,
    ) -> Tuple[str, str, str]:
        """
        Generate authorization URL with PKCE

        Args:
            scopes: List of OAuth2 scopes
            state: State parameter for CSRF protection
            resource: Optional resource parameter
            **kwargs: Additional parameters

        Returns:
            Tuple of (authorization_url, state, code_verifier)
        """
        if not state:
            state = generate_state()

        # Generate PKCE pair
        code_verifier, code_challenge = generate_pkce_pair()

        auth_params = {
            "client_id": self.client_config.client_id,
            "redirect_uri": self.client_config.redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "requested_actor": self.agent_config.agent_id,
            "resource": resource,
        }

        auth_params.update(kwargs)

        auth_url = build_authorization_url(
            base_url=self.server_config.authorize_endpoint, params=auth_params
        )

        logger.debug(f"Generated authorization URL with PKCE and state: {state}")
        return auth_url, state, code_verifier

    async def get_obo_token_with_pkce(
        self,
        scopes: Optional[List[str]] = None,
        auth_code: Optional[str] = None,
        code_verifier: Optional[str] = None,
        agent_token: Optional[OAuthToken] = None,
        resource: Optional[str] = None,
    ) -> OAuthToken:
        """
        Get on-behalf-of token for user context using authorization code flow

        Args:
            scopes: List of OAuth2 scopes
            auth_code: Authorization code received from user authentication
            code_verifier: Code verifier for PKCE
            resource: Optional resource parameter

        Returns:
            OAuth2 token for the user

        Raises:
            AIAuthenticationError: If user authentication fails
        """
        try:

            if not auth_code:
                raise AIAuthenticationError("Authorization failed or cancelled")

            if scopes is None:
                scopes = []

            # Exchange code for token
            token_request = AuthorizationCodeRequest(
                code=auth_code,
                redirect_uri=self.client_config.redirect_uri,
                code_verifier=code_verifier,
                actor_token=agent_token.access_token if agent_token else None,
                scope=" ".join(scopes),
            )

            token = await self.token_client.request_token(token_request)
            logger.info("Successfully obtained obo token")

            return token

        except AIAuthenticationError:
            raise
        except Exception as e:
            logger.error(f"User authentication failed: {e}")
            raise AIAuthenticationError(f"User authentication failed: {e}")

    async def refresh_token(
        self, refresh_token: str, scopes: Optional[List[str]] = None
    ) -> OAuthToken:
        """
        Refresh OAuth2 token

        Args:
            refresh_token: Refresh token
            scopes: Optional list of OAuth2 scopes

        Returns:
            New OAuth2 token
        """
        try:
            scope_string = " ".join(scopes) if scopes else None
            token = await self.token_client.refresh_token(refresh_token, scope_string)
            logger.info("Successfully refreshed token")
            return token
        except Exception as e:
            logger.error(f"Token refresh failed: {e}")
            raise AIAuthenticationError(f"Token refresh failed: {e}")

    async def revoke_token(
        self, token: str, token_type_hint: str = "access_token"
    ) -> bool:
        """
        Revoke OAuth2 token

        Args:
            token: Token to revoke
            token_type_hint: Type of token

        Returns:
            True if revocation was successful
        """
        try:
            return await self.token_client.revoke_token(token, token_type_hint)
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False

    def get_agent_context(self) -> Dict[str, Any]:
        """
        Get agent context information

        Returns:
            Agent context dictionary
        """
        context = {}

        if self.agent_config:
            context.update(
                {
                    "agent_name": self.agent_config.agent_name,
                    "agent_id": self.agent_config.agent_id,
                }
            )

        if self.session_config:
            context.update(
                {
                    "session_id": self.session_config.session_id,
                    "user_id": self.session_config.user_id,
                    "session_context": self.session_config.context,
                }
            )

        return context

    async def close(self):
        """Close the agent auth manager and cleanup resources"""
        await self.token_client.close()
