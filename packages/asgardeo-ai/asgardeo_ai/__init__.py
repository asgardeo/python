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
)
from .exceptions import (
    AIAuthenticationError,
    AgentAuthenticationError,
)

__all__ = [
    "AgentAuthManager",
    "AgentConfig",
    "AIAuthenticationError",
    "AgentAuthenticationError",
]
