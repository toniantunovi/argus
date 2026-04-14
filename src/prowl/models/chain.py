"""Chain models for multi-finding attack chains."""
from __future__ import annotations

import enum

from pydantic import BaseModel, Field

from prowl.models.core import Severity


class ChainType(str, enum.Enum):
    PRIVILEGE_CHAIN = "privilege_chain"
    SANDBOX_ESCAPE = "sandbox_escape"
    AUTH_BYPASS_CHAIN = "auth_bypass_chain"
    RCE_CHAIN = "rce_chain"
    MITIGATION_BYPASS = "mitigation_bypass"

class ChainComponent(BaseModel):
    finding_id: str
    role: str = ""  # what this finding contributes to the chain

class Chain(BaseModel):
    chain_id: str
    chain_type: ChainType | None = None
    components: list[ChainComponent] = Field(default_factory=list)
    combined_severity: Severity = Severity.HIGH
    description: str = ""
    reasoning: str = ""
    validated: bool = False

class ChainEvaluation(BaseModel):
    """LLM evaluation of a potential chain."""
    is_chain: bool = False
    chain_type: ChainType | None = None
    combined_severity: Severity = Severity.HIGH
    description: str = ""
    reasoning: str = ""
