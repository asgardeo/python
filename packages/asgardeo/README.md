# Asgardeo Python SDK

A Python SDK for WSO2 Asgardeo OAuth2 authentication and identity management.

## Features

- OAuth2 token operations (request, refresh, revoke)
- Native authentication for mobile/desktop apps
- Support for various authenticators (Username/Password, TOTP, Email OTP, SMS OTP)
- PKCE support for enhanced security

## Installation

```bash
pip install asgardeo
```

### Optional Dependencies

For JWT token validation:

```bash
pip install asgardeo[jwt]
```

## Quick Start

### Token Client for OAuth2 Operations

```python
from asgardeo import TokenClient, ClientConfig, ServerConfig, AuthorizationCodeRequest

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

# Create token client
token_client = TokenClient(client_config, server_config)

# Request token using authorization code
request = AuthorizationCodeRequest(
    code="authorization-code-from-callback",
    code_verifier="pkce-code-verifier"
)
token = await token_client.request_token(request)

# Refresh token
refreshed_token = await token_client.refresh_token(token.refresh_token)

# Revoke token
await token_client.revoke_token(token.access_token)
```

### Native Authentication

```python
from asgardeo import NativeAuthClient, ClientConfig, ServerConfig

# Create native auth client
native_client = NativeAuthClient(client_config, server_config)

# Initialize authentication
response = await native_client.initiate_authentication(
    scopes=["openid", "profile"],
    redirect_uri="http://localhost:8080/callback",
    state="random-state"
)

# Authenticate with username/password
if response.authenticators:
    auth_response = await native_client.authenticate_with_username_password(
        flow_id=response.flow_id,
        authenticator_id=response.authenticators[0].authenticator_id,
        username="user@example.com",
        password="password"
    )

# Continue with TOTP if required
if auth_response.flow_status == "INCOMPLETE":
    final_response = await native_client.authenticate_with_totp(
        flow_id=response.flow_id,
        authenticator_id=auth_response.next_step.authenticators[0].authenticator_id,
        totp_token="123456"
    )
```
