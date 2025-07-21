# Asgardeo AI SDK

A Python SDK for WSO2 Asgardeo OAuth2 authentication specifically designed for AI agents and frameworks.

## Features

- AI agent authentication
- On-Behalf-Of (OBO) token flows for user delegation
- PKCE support for secure authorization flows
- Built on top of the core Asgardeo SDK

## Installation

```bash
pip install asgardeo-ai
```

**Note**: This package currently requires the core `asgardeo` package to be installed separately.

## Quick Start

```python
# Import from the core asgardeo package
from asgardeo import ClientConfig, ServerConfig

# Import AI-specific components (Note: direct import from asgardeo_ai currently has issues)
from asgardeo_ai.agent_auth_manager import AgentAuthManager
from asgardeo_ai.models import AgentConfig

# Configure client
client_config = ClientConfig(
    client_id="your-client-id",
    client_secret="your-client-secret",
    redirect_uri="http://localhost:8080/callback"
)

# Configure server
server_config = ServerConfig(
    base_url="https://api.asgardeo.io/t/yourorg"
)

# Configure agent
agent_config = AgentConfig(
    agent_name="my-ai-agent",
    agent_id="agent-123",
    agent_secret="your-agent-secret"
)

# Create auth manager
auth_manager = AgentAuthManager(client_config, server_config, agent_config)

# Get agent token using TOTP
agent_token = await auth_manager.get_agent_token(["openid", "profile"])
```

## Agent Authentication

The SDK supports authentication for AI agents:

```python
try:
    # Agent authenticates using agent credentials
    agent_token = await auth_manager.get_agent_token(["openid", "profile"])
    print(f"Agent authenticated: {agent_token.access_token}")
except Exception as e:
    print(f"Authentication failed: {e}")
```

## Authorization URL Generation with PKCE

Generate authorization URLs for OAuth2 flows:

```python
# Generate authorization URL with PKCE
auth_url, state, code_verifier = auth_manager.get_authorization_url_with_pkce(
    scopes=["openid", "profile"],
    state="random-state"
)
print(f"Visit: {auth_url}")

# After user authorization, exchange code for token
obo_token = await auth_manager.get_obo_token_with_pkce(
    scopes=["openid", "profile"],
    auth_code="authorization-code-from-callback",
    code_verifier=code_verifier,
    agent_token=agent_token
)
```

## Token Management

```python
# Refresh tokens
refreshed_token = await auth_manager.refresh_token(
    refresh_token=agent_token.refresh_token,
    scopes=["openid", "profile"]
)

# Revoke tokens
success = await auth_manager.revoke_token(
    token=agent_token.access_token,
    token_type_hint="access_token"
)

# Get agent context
context = auth_manager.get_agent_context()
print(f"Agent context: {context}")
```
