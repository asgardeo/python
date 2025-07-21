"""
OAuth2 utility functions
"""

import base64
import hashlib
import secrets
from typing import Tuple, Dict, List, Union
from urllib.parse import urlencode, urlparse, parse_qs


def generate_state() -> str:
    """Generate a secure random state parameter for OAuth2 flows"""
    return secrets.token_urlsafe(32)


def generate_pkce_pair() -> Tuple[str, str]:
    """
    Generate PKCE code verifier and code challenge pair

    Returns:
        Tuple of (code_verifier, code_challenge)
    """
    # Generate code verifier (43-128 characters)
    code_verifier = (
        base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("utf-8").rstrip("=")
    )

    # Generate code challenge (SHA256 hash of verifier)
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("utf-8")).digest())
        .decode("utf-8")
        .rstrip("=")
    )

    return code_verifier, code_challenge


def normalize_scope(scopes: Union[str, List[str]]) -> str:
    """Normalize scope parameter to space-separated string"""
    if isinstance(scopes, str):
        return scopes
    elif isinstance(scopes, list):
        return " ".join(scopes)
    else:
        return ""


def build_authorization_url(base_url: str, params: Dict[str, str]) -> str:
    """Build authorization URL with parameters"""
    return f"{base_url}?{urlencode(params)}"


def extract_callback_params(url: str) -> Dict[str, List[str]]:
    """Extract parameters from OAuth2 callback URL"""
    parsed = urlparse(url)

    # Check for parameters in fragment (implicit flow)
    if parsed.fragment:
        return parse_qs(parsed.fragment, keep_blank_values=True)

    # Check for parameters in query string (authorization code flow)
    if parsed.query:
        return parse_qs(parsed.query, keep_blank_values=True)

    return {}


def validate_redirect_uri(redirect_uri: str) -> bool:
    """Validate redirect URI format"""
    try:
        parsed = urlparse(redirect_uri)
        return parsed.scheme in ("http", "https") and parsed.netloc
    except Exception:
        return False


def encode_basic_auth(username: str, password: str) -> str:
    """Encode username and password for HTTP Basic authentication"""
    credentials = f"{username}:{password}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    return f"Basic {encoded}"


def mask_sensitive_data(data: str, mask_char: str = "*", visible_chars: int = 4) -> str:
    """Mask sensitive data for logging"""
    if not data or len(data) <= visible_chars * 2:
        return mask_char * len(data) if data else ""

    return (
        data[:visible_chars]
        + mask_char * (len(data) - visible_chars * 2)
        + data[-visible_chars:]
    )
