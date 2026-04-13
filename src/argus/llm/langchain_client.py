"""LangChain-based LLM client supporting multiple providers."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from argus.config import LLMConfig
from argus.models.context import ExploitContext, FindingContext, FunctionContext
from argus.models.finding import Finding
from argus.models.hypothesis import HypothesisResponse

logger = logging.getLogger(__name__)

# Default env var names per provider
_DEFAULT_API_KEY_ENVS = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "google": "GOOGLE_API_KEY",
}


class LangChainClient:
    """LLM client that uses LangChain for multi-provider support."""

    def __init__(self, config: LLMConfig):
        self.config = config
        self._models: dict[str, Any] = {}

    def check_session(self) -> None:
        """Validate that the required API key is available."""
        provider = self.config.provider
        if provider == "ollama":
            return
        env_var = self.config.api_key_env or _DEFAULT_API_KEY_ENVS.get(provider)
        if env_var and not os.environ.get(env_var):
            raise RuntimeError(
                f"API key not found. Set the {env_var} environment variable "
                f"for the '{provider}' provider, or configure 'api_key_env' in argus.yml."
            )

    def _get_model(self, layer: str = "default") -> Any:
        if layer not in self._models:
            self._models[layer] = self._create_model(layer)
        return self._models[layer]

    def _create_model(self, layer: str) -> Any:
        layer_config = getattr(self.config, layer, None) if layer != "default" else None
        provider = (layer_config and layer_config.provider) or self.config.provider
        model = (layer_config and layer_config.model) or self.config.model
        temperature = (layer_config and layer_config.temperature)
        if temperature is None:
            temperature = self.config.temperature
        base_url = self.config.base_url
        api_key_env = self.config.api_key_env or _DEFAULT_API_KEY_ENVS.get(provider)
        api_key = os.environ.get(api_key_env, "") if api_key_env else None

        if provider == "openai":
            from langchain_openai import ChatOpenAI
            kwargs: dict[str, Any] = {"model": model, "temperature": temperature}
            if api_key:
                kwargs["api_key"] = api_key
            if base_url:
                kwargs["base_url"] = base_url
            return ChatOpenAI(**kwargs)
        elif provider == "anthropic":
            from langchain_anthropic import ChatAnthropic
            kwargs = {"model": model, "temperature": temperature}
            if api_key:
                kwargs["api_key"] = api_key
            return ChatAnthropic(**kwargs)
        elif provider == "google":
            from langchain_google_genai import ChatGoogleGenerativeAI
            kwargs = {"model": model, "temperature": temperature}
            if api_key:
                kwargs["google_api_key"] = api_key
            return ChatGoogleGenerativeAI(**kwargs)
        elif provider == "ollama":
            from langchain_ollama import ChatOllama
            kwargs = {"model": model, "temperature": temperature}
            if base_url:
                kwargs["base_url"] = base_url
            return ChatOllama(**kwargs)
        else:
            raise ValueError(
                f"Unknown LLM provider: '{provider}'. "
                f"Supported: openai, anthropic, google, ollama"
            )

    # Per-layer default output caps. Tuned to give modern long-context models
    # plenty of headroom for structured JSON responses (schemas + reasoning +
    # PoC code). Override per layer via argus.yml (llm.<layer>.max_tokens).
    _DEFAULT_MAX_TOKENS = {
        "hypothesis": 16000,
        "triage": 8000,
        "validation": 32000,
    }

    def _layer_max_tokens(self, layer: str, default: int) -> int:
        """Resolve max_tokens for a layer: config override wins, else default."""
        layer_config = getattr(self.config, layer, None)
        if layer_config is not None and layer_config.max_tokens is not None:
            return layer_config.max_tokens
        return default

    async def _sample(
        self, system_prompt: str, user_prompt: str, max_tokens: int = 2000, layer: str = "default",
    ) -> str:
        from langchain_core.messages import HumanMessage, SystemMessage
        model = self._get_model(layer)
        messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
        response = await model.ainvoke(messages, max_tokens=max_tokens)
        content = response.content
        if isinstance(content, list):
            return "".join(block.get("text", "") if isinstance(block, dict) else str(block) for block in content)
        return str(content)

    # --- Domain methods (identical interface to former MCPSamplingClient) ---

    async def hypothesize(self, context: FunctionContext) -> HypothesisResponse:
        from argus.hypothesis.prompts import build_hypothesis_prompt, get_hypothesis_system_prompt
        prompt = build_hypothesis_prompt(context)
        max_tokens = self._layer_max_tokens("hypothesis", self._DEFAULT_MAX_TOKENS["hypothesis"])
        response_text = await self._sample(
            get_hypothesis_system_prompt(), prompt, max_tokens=max_tokens, layer="hypothesis",
        )
        return self._parse_response(response_text, HypothesisResponse)

    async def triage(self, context: FindingContext) -> dict:
        from argus.triage.prompts import TRIAGE_SYSTEM_PROMPT, build_triage_prompt
        prompt = build_triage_prompt(context)
        max_tokens = self._layer_max_tokens("triage", self._DEFAULT_MAX_TOKENS["triage"])
        response_text = await self._sample(TRIAGE_SYSTEM_PROMPT, prompt, max_tokens=max_tokens, layer="triage")
        return self._parse_json(response_text)

    async def generate_poc(self, context: ExploitContext) -> dict:
        from argus.validation.prompts import POC_SYSTEM_PROMPT, build_poc_prompt
        prompt = build_poc_prompt(context)
        max_tokens = self._layer_max_tokens("validation", self._DEFAULT_MAX_TOKENS["validation"])
        response_text = await self._sample(POC_SYSTEM_PROMPT, prompt, max_tokens=max_tokens, layer="validation")
        return self._parse_poc_response(response_text)

    async def evaluate_chain(self, findings: list[Finding], rubric: str) -> dict:
        from argus.triage.prompts import CHAIN_SYSTEM_PROMPT, build_chain_prompt
        prompt = build_chain_prompt(findings, rubric)
        max_tokens = self._layer_max_tokens("triage", self._DEFAULT_MAX_TOKENS["triage"])
        response_text = await self._sample(CHAIN_SYSTEM_PROMPT, prompt, max_tokens=max_tokens, layer="triage")
        return self._parse_json(response_text)

    async def generate_patch(self, context: ExploitContext, poc_code: str) -> str:
        from argus.validation.prompts import PATCH_SYSTEM_PROMPT, build_patch_prompt
        prompt = build_patch_prompt(context, poc_code)
        max_tokens = self._layer_max_tokens("validation", self._DEFAULT_MAX_TOKENS["validation"])
        response_text = await self._sample(PATCH_SYSTEM_PROMPT, prompt, max_tokens=max_tokens, layer="validation")
        return response_text

    async def batch_triage(self, contexts: list[FindingContext]) -> list[dict]:
        from argus.triage.prompts import BATCH_TRIAGE_SYSTEM_PROMPT, build_batch_triage_prompt
        prompt = build_batch_triage_prompt(contexts)
        max_tokens = self._layer_max_tokens("triage", self._DEFAULT_MAX_TOKENS["triage"])
        response_text = await self._sample(BATCH_TRIAGE_SYSTEM_PROMPT, prompt, max_tokens=max_tokens, layer="triage")
        return self._parse_json_list(response_text)

    # --- Response parsing ---

    @staticmethod
    def _extract_json_text(text: str) -> str:
        """Extract JSON from LLM response, stripping markdown fences."""
        import re
        text = text.strip()
        # Strip markdown code fences: ```json ... ``` or ``` ... ```
        m = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
        if m:
            text = m.group(1).strip()
        return text

    @staticmethod
    def _fix_json(text: str) -> str:
        """Best-effort fix of common LLM JSON mistakes.

        Handles:
        - Unquoted property names: {classification: "x"} -> {"classification": "x"}
        - Single-quoted strings: {'key': 'val'} -> {"key": "val"}
        - Trailing commas: {"a": 1,} -> {"a": 1}
        - Unescaped newlines/control chars inside string values
        """
        import re

        # --- Fix unescaped control characters inside JSON string values ---
        # Walk the string character by character, tracking whether we're inside
        # a JSON string literal.  When we are, replace raw control characters
        # with their escaped equivalents so json.loads won't choke.
        out: list[str] = []
        in_string = False
        i = 0
        while i < len(text):
            ch = text[i]
            if in_string:
                if ch == '\\':
                    # Escaped character – pass through as-is
                    out.append(ch)
                    if i + 1 < len(text):
                        i += 1
                        out.append(text[i])
                elif ch == '"':
                    out.append(ch)
                    in_string = False
                elif ch == '\n':
                    out.append('\\n')
                elif ch == '\r':
                    out.append('\\r')
                elif ch == '\t':
                    out.append('\\t')
                elif ord(ch) < 0x20:
                    out.append(f'\\u{ord(ch):04x}')
                else:
                    out.append(ch)
            else:
                out.append(ch)
                if ch == '"':
                    in_string = True
            i += 1
        text = ''.join(out)

        # --- Fix single-quoted strings (keys AND values) ---
        # Replace single-quoted strings with double-quoted, being careful not
        # to touch apostrophes inside double-quoted strings.  We walk character
        # by character, tracking whether we're inside a double-quoted string.
        out2: list[str] = []
        in_dq = False
        j = 0
        while j < len(text):
            ch = text[j]
            if in_dq:
                out2.append(ch)
                if ch == '\\' and j + 1 < len(text):
                    j += 1
                    out2.append(text[j])
                elif ch == '"':
                    in_dq = False
            elif ch == '"':
                out2.append(ch)
                in_dq = True
            elif ch == "'":
                # Replace single quote with double quote
                out2.append('"')
            else:
                out2.append(ch)
            j += 1
        text = ''.join(out2)

        # --- Fix unquoted property names ---
        # Match a property-name position: after { or , followed by optional
        # whitespace, then an unquoted identifier, then optional whitespace + colon.
        text = re.sub(
            r'(?<=[{,])\s*([a-zA-Z_]\w*)\s*:',
            r' "\1":',
            text,
        )

        # --- Fix trailing commas before } or ] ---
        text = re.sub(r',\s*([}\]])', r'\1', text)

        return text

    @staticmethod
    def _find_json_object(text: str) -> str:
        """Find the outermost balanced { ... } in text."""
        start = text.find('{')
        if start < 0:
            return text
        depth = 0
        in_str = False
        i = start
        while i < len(text):
            ch = text[i]
            if in_str:
                if ch == '\\':
                    i += 1  # skip escaped char
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == '{':
                    depth += 1
                elif ch == '}':
                    depth -= 1
                    if depth == 0:
                        return text[start:i + 1]
            i += 1
        # Unbalanced – return from start anyway, json.loads will report a clear error
        return text[start:]

    @staticmethod
    def _find_json_array(text: str) -> str:
        """Find the outermost balanced [ ... ] in text."""
        start = text.find('[')
        if start < 0:
            return text
        depth = 0
        in_str = False
        i = start
        while i < len(text):
            ch = text[i]
            if in_str:
                if ch == '\\':
                    i += 1
                elif ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == '[':
                    depth += 1
                elif ch == ']':
                    depth -= 1
                    if depth == 0:
                        return text[start:i + 1]
            i += 1
        return text[start:]

    def _robust_json_loads(self, text: str) -> Any:
        """Parse JSON with fallback repair for common LLM quirks."""
        # Fast path: try parsing as-is
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Slow path: apply fixes and retry
        fixed = self._fix_json(text)
        return json.loads(fixed)

    def _parse_response(self, text: str, model_class):
        raw = text
        extracted = self._extract_json_text(text)
        extracted = self._find_json_object(extracted)
        extracted = self._fix_json(extracted)
        try:
            return model_class.model_validate_json(extracted)
        except Exception:
            # Try normalizing field names and structure before giving up
            try:
                data = json.loads(extracted)
                data = self._normalize_hypothesis_fields(data)
                return model_class.model_validate(data)
            except Exception:
                self._log_parse_failure(model_class.__name__, raw, extracted)
                raise

    @staticmethod
    def _log_parse_failure(target: str, raw: str, extracted: str) -> None:
        """Log the raw and post-extraction LLM text when parsing fails."""
        logger.error(
            "LLM response parse failure (%s).\n"
            "--- extracted (%d chars) ---\n%s\n"
            "--- raw (%d chars) ---\n%s\n"
            "--- end ---",
            target,
            len(extracted), extracted,
            len(raw), raw,
        )

    @staticmethod
    def _normalize_hypothesis_fields(data: dict) -> dict:
        """Normalize common LLM field name variations for HypothesisResponse."""
        # If the LLM returned a list directly instead of wrapping in {"hypotheses": [...]}
        if isinstance(data, list):
            data = {"hypotheses": data}

        # If the LLM returned a single hypothesis without wrapping in a list
        if "hypotheses" not in data and "title" in data:
            data = {"hypotheses": [data]}

        # Common field name variations in hypothesis items
        _FIELD_ALIASES = {
            "vuln_type": "category", "vulnerability_type": "category",
            "type": "category", "vuln_category": "category",
            "lines": "affected_lines", "line_numbers": "affected_lines",
            "confidence_score": "confidence", "score": "confidence",
            "attack_path": "attack_scenario", "exploit_scenario": "attack_scenario",
            "analysis": "reasoning", "explanation": "reasoning",
            "sev": "severity",
        }

        if "hypotheses" in data and isinstance(data["hypotheses"], list):
            for hyp in data["hypotheses"]:
                if not isinstance(hyp, dict):
                    continue
                for alias, canonical in _FIELD_ALIASES.items():
                    if alias in hyp and canonical not in hyp:
                        hyp[canonical] = hyp.pop(alias)
                # Ensure affected_lines is a list of ints
                if "affected_lines" in hyp and not isinstance(hyp["affected_lines"], list):
                    hyp["affected_lines"] = []

        return data

    def _parse_json(self, text: str) -> dict:
        raw = text
        extracted = self._extract_json_text(text)
        extracted = self._find_json_object(extracted)
        try:
            return self._robust_json_loads(extracted)
        except Exception:
            self._log_parse_failure("json-object", raw, extracted)
            raise

    def _parse_json_list(self, text: str) -> list[dict]:
        raw = text
        extracted = self._extract_json_text(text)
        extracted = self._find_json_array(extracted)
        try:
            return self._robust_json_loads(extracted)
        except Exception:
            self._log_parse_failure("json-array", raw, extracted)
            raise

    def _parse_poc_response(self, text: str) -> dict:
        """Parse PoC response: code in a fenced block + metadata in JSON.

        Falls back to regular JSON parsing if the fenced-block format isn't found.
        """
        import re

        # Try to extract code from a fenced code block
        fence_match = re.search(
            r"```(\w+)?\s*\n(.*?)```",
            text,
            re.DOTALL,
        )
        if fence_match:
            lang_hint = fence_match.group(1) or ""
            code = fence_match.group(2).strip()

            # Extract JSON metadata after the code fence
            after_fence = text[fence_match.end():]
            metadata: dict = {}
            try:
                json_text = self._find_json_object(after_fence)
                metadata = self._robust_json_loads(json_text)
            except (json.JSONDecodeError, ValueError):
                pass

            return {
                "code": code,
                "language": metadata.get("language", lang_hint),
                "description": metadata.get("description", ""),
                "setup_instructions": metadata.get("setup_instructions", ""),
            }

        # Fallback: try parsing as regular JSON (old format)
        return self._parse_json(text)
