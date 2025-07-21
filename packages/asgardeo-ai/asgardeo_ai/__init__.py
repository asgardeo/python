"""
Asgardeo AI Core - AI-enhanced OAuth2 authentication

This module provides AI agent-specific authentication capabilities including:
- AuthManager with AI agent support
- AgentConfig for TOTP authentication
- SessionConfig for multi-session management
- AI-specific OAuth2 flows
"""

from .agent_auth_manager import AgentAuthManager
from .models import (
    AgentConfig,
    SessionConfig,
    AuthRequestMessage,
    AuthResponseMessage,
    AIAuthConfig,
)
from .flows import AgentTOTPFlow, OnBehalfOfFlow
from .storage import SessionTokenStore, ContextTokenStore
from .exceptions import (
    AIAuthenticationError,
    AgentAuthenticationError,
    SessionExpiredError,
    UserConsentRequiredError,
    FrameworkNotSupportedError,
    ToolExecutionError,
)

__all__ = [
    "AuthManager",
    "AgentConfig",
    "SessionConfig",
    "AuthRequestMessage",
    "AuthResponseMessage",
    "AIAuthConfig",
    "AgentTOTPFlow",
    "OnBehalfOfFlow",
    "SessionTokenStore",
    "ContextTokenStore",
    "AIAuthenticationError",
    "AgentAuthenticationError",
    "SessionExpiredError",
    "UserConsentRequiredError",
    "FrameworkNotSupportedError",
    "ToolExecutionError",
]
