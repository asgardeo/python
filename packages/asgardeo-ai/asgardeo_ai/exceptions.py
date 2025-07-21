"""
AI-specific exceptions for Asgardeo AI SDK
"""

import sys
import os

sys.path.append(os.path.join(os.path.dirname(__file__), "..", "..", "..", "asgardeo"))

from asgardeo.auth.exceptions import OAuthError


class AIAuthenticationError(OAuthError):
    """Base AI authentication error"""

    pass


class AgentAuthenticationError(AIAuthenticationError):
    """Agent authentication failed"""

    pass
