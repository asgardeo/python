"""
AI-specific data models for Asgardeo AI SDK
"""

from typing import Dict, List, Optional, Any
from pydantic import BaseModel, Field, field_validator


class AgentConfig(BaseModel):
    """Configuration for AI agent authentication"""

    agent_name: str
    agent_id: str
    agent_secret: str  # TOTP secret

    @field_validator("agent_name")
    @classmethod
    def validate_agent_name(cls, v):
        if not v or not v.strip():
            raise ValueError("agent_name cannot be empty")
        return v.strip()

    @field_validator("agent_id")
    @classmethod
    def validate_agent_id(cls, v):
        if not v or not v.strip():
            raise ValueError("agent_id cannot be empty")
        return v.strip()

    @field_validator("agent_secret")
    @classmethod
    def validate_agent_secret(cls, v):
        if not v or not v.strip():
            raise ValueError("agent_secret cannot be empty")
        return v.strip()

    def __str__(self) -> str:
        """String representation masking sensitive data"""
        return f"AgentConfig(agent_name={self.agent_name}, agent_id={self.agent_id}, agent_secret=***)"
