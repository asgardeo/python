# Examples

This directory contains examples for using the Asgardeo Python SDKs.

## Structure

- `asgardeo/` - Examples for the core Asgardeo SDK
- `asgardeo-ai/` - Examples for the Asgardeo AI SDK

## Setup

### 1. Create a virtual environment

From the repository root (`sdk/python`):

```bash
python3 -m venv .venv
source .venv/bin/activate        # macOS/Linux
# .venv\Scripts\activate         # Windows
```

### 2. Install the packages

Install both packages in editable mode so local source changes are picked up immediately:

```bash
pip install -e packages/asgardeo -e packages/asgardeo-ai
```

### 3. Configure credentials

Open the example file you want to run and replace the placeholder values with your actual Asgardeo credentials:

```python
config = AsgardeoConfig(
    base_url="https://api.asgardeo.io/t/<your-org>",
    client_id="<your-client-id>",
    redirect_uri="<your-redirect-uri>",
    client_secret="<your-client-secret>"
)
```

## Available Examples

| Example | Description |
|---------|-------------|
| `asgardeo/native_auth.py` | App-native authentication (username/password without browser redirect) |
| `asgardeo-ai/agent_auth.py` | AI agent token acquisition using native auth |
| `asgardeo-ai/obo_flow.py` | On-Behalf-Of (OBO) token flow via authorization code |
| `asgardeo-ai/ciba_obo_flow.py` | On-Behalf-Of (OBO) token flow via CIBA with polling |

## Running Examples

Make sure the virtual environment is activated, then run any example from the repository root:

```bash
python examples/asgardeo/native_auth.py
python examples/asgardeo-ai/agent_auth.py
python examples/asgardeo-ai/obo_flow.py
python examples/asgardeo-ai/ciba_obo_flow.py
```

## Asgardeo Prerequisites

Before running the examples, ensure your application is configured in the Asgardeo Console:

- **Native auth / Agent auth**: Enable **App-Native Authentication** in the Login Flow tab
- **OBO flow**: Enable **Token Exchange** grant type in the Protocol tab
- **CIBA OBO flow**: Enable **CIBA** grant type in the Protocol tab and configure at least one notification channel (Email, SMS, or External)
