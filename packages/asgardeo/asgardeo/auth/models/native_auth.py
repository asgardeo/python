"""
App Native Authentication API models
"""

from enum import Enum
from typing import Dict, Any, List, Optional, Union
from pydantic import BaseModel, Field


class FlowStatus(str, Enum):
    """Authentication flow status"""

    INCOMPLETE = "INCOMPLETE"
    FAIL_INCOMPLETE = "FAIL_INCOMPLETE"
    SUCCESS_COMPLETED = "SUCCESS_COMPLETED"


class StepType(str, Enum):
    """Authentication step types"""

    MULTI_OPTIONS_PROMPT = "MULTI_OPTIONS_PROMPT"
    AUTHENTICATOR_PROMPT = "AUTHENTICATOR_PROMPT"


class AuthenticatorType(str, Enum):
    """Authenticator types"""

    USERNAME_PASSWORD = "username-password-authenticator"
    TOTP = "totp-authenticator"
    EMAIL_OTP = "email-otp-authenticator"
    SMS_OTP = "sms-otp-authenticator"
    FIDO2 = "fido2-authenticator"
    PASSKEY = "passkey-authenticator"


class NativeAuthInitRequest(BaseModel):
    """Request to initiate native authentication"""

    response_type: str = "code"
    client_id: str
    response_mode: str = "direct"
    redirect_uri: str
    scope: Optional[str] = None
    state: Optional[str] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = "S256"

    def to_url_params(self) -> Dict[str, str]:
        """Convert to URL parameters"""
        params = {}
        for key, value in self.model_dump().items():
            if value is not None:
                params[key] = str(value)
        return params


class Authenticator(BaseModel):
    """Authenticator information"""

    authenticator_id: str = Field(alias="authenticatorId")
    authenticator: str
    idp: str
    metadata: Optional[Dict[str, Any]] = None
    required_params: Optional[List[str]] = Field(
        default_factory=list, alias="requiredParams"
    )

    class Config:
        populate_by_name = True


class NextStep(BaseModel):
    """Next step in authentication flow"""

    step_type: StepType = Field(alias="stepType")
    authenticators: List[Authenticator]
    messages: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    class Config:
        populate_by_name = True


class AuthData(BaseModel):
    """Authentication data from successful completion"""

    code: Optional[str] = None
    session_state: Optional[str] = None
    state: Optional[str] = None

    class Config:
        populate_by_name = True


class NativeAuthResponse(BaseModel):
    """Response from native authentication API"""

    flow_id: Optional[str] = Field(None, alias="flowId")
    flow_status: FlowStatus = Field(alias="flowStatus")
    flow_type: Optional[str] = Field(None, alias="flowType")
    next_step: Optional[NextStep] = Field(None, alias="nextStep")
    auth_data: Optional[AuthData] = Field(None, alias="authData")
    links: Optional[List[Dict[str, Any]]] = Field(default_factory=list)

    class Config:
        populate_by_name = True


class AuthenticatorParams(BaseModel):
    """Base authenticator parameters"""

    pass


class UsernamePasswordParams(AuthenticatorParams):
    """Username/password authenticator parameters"""

    username: str
    password: str


class TOTPParams(AuthenticatorParams):
    """TOTP authenticator parameters"""

    token: str


class EmailOTPParams(AuthenticatorParams):
    """Email OTP authenticator parameters"""

    otpCode: str


class SMSOTPParams(AuthenticatorParams):
    """SMS OTP authenticator parameters"""

    otpCode: str


class FIDO2Params(AuthenticatorParams):
    """FIDO2 authenticator parameters"""

    credential: Dict[str, Any]


class PasskeyParams(AuthenticatorParams):
    """Passkey authenticator parameters"""

    credential: Dict[str, Any]


class SelectedAuthenticator(BaseModel):
    """Selected authenticator for authentication step"""

    authenticator_id: str = Field(alias="authenticatorId")
    params: Union[
        UsernamePasswordParams,
        TOTPParams,
        EmailOTPParams,
        SMSOTPParams,
        FIDO2Params,
        PasskeyParams,
        Dict[str, Any],
    ]

    class Config:
        populate_by_name = True


class NativeAuthStepRequest(BaseModel):
    """Request for authentication step"""

    flow_id: str = Field(alias="flowId")
    selected_authenticator: SelectedAuthenticator = Field(alias="selectedAuthenticator")

    class Config:
        populate_by_name = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for HTTP request"""
        return self.model_dump(by_alias=True, exclude_none=True)


class NativeAuthError(BaseModel):
    """Native authentication error"""

    code: str
    message: str
    description: Optional[str] = None
    trace_id: Optional[str] = Field(None, alias="traceId")

    class Config:
        populate_by_name = True


class NativeAuthConfig(BaseModel):
    """Configuration for native authentication"""

    client_id: str
    redirect_uri: str
    scopes: List[str] = Field(default_factory=list)
    response_mode: str = "direct"

    def to_init_request(self, state: Optional[str] = None) -> NativeAuthInitRequest:
        """Convert to init request"""
        return NativeAuthInitRequest(
            client_id=self.client_id,
            redirect_uri=self.redirect_uri,
            scope=" ".join(self.scopes) if self.scopes else None,
            state=state,
            response_mode=self.response_mode,
        )
