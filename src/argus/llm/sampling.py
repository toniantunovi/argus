"""LLM client protocol and factory."""
from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from argus.models.context import ExploitContext, FindingContext, FunctionContext
from argus.models.finding import Finding
from argus.models.hypothesis import HypothesisResponse

if TYPE_CHECKING:
    from argus.config import ArgusConfig


class LLMClient(Protocol):
    """Protocol for LLM client - allows mocking."""
    async def hypothesize(self, context: FunctionContext) -> HypothesisResponse: ...
    async def triage(self, context: FindingContext) -> dict: ...
    async def generate_poc(self, context: ExploitContext) -> dict: ...
    async def evaluate_chain(self, findings: list[Finding], rubric: str) -> dict: ...
    async def generate_patch(self, context: ExploitContext, poc_code: str) -> str: ...
    async def batch_triage(self, contexts: list[FindingContext]) -> list[dict]: ...
    def check_session(self) -> None: ...


def create_llm_client(config: ArgusConfig) -> LLMClient:
    """Create an LLM client from configuration."""
    from argus.llm.langchain_client import LangChainClient
    return LangChainClient(config.llm)
