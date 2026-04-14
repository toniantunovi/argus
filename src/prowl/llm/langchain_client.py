"""LangChain-based LLM client supporting multiple providers."""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from prowl.config import LLMConfig
from prowl.models.context import ExploitContext, FindingContext, FunctionContext
from prowl.models.finding import Finding
from prowl.models.hypothesis import HypothesisResponse

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
                f"for the '{provider}' provider, or configure 'api_key_env' in prowl.yml."
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
    # PoC code). Override per layer via prowl.yml (llm.<layer>.max_tokens).
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
        from prowl.hypothesis.prompts import build_hypothesis_prompt, get_hypothesis_system_prompt
        prompt = build_hypothesis_prompt(context)
        max_tokens = self._layer_max_tokens("hypothesis", self._DEFAULT_MAX_TOKENS["hypothesis"])
        response_text = await self._sample(
            get_hypothesis_system_prompt(), prompt, max_tokens=max_tokens, layer="hypothesis",
        )
        return self._parse_response(response_text, HypothesisResponse)

    async def triage(self, context: FindingContext) -> dict:
        from prowl.triage.prompts import TRIAGE_SYSTEM_PROMPT, build_triage_prompt
        prompt = build_triage_prompt(context)
        max_tokens = self._layer_max_tokens("triage", self._DEFAULT_MAX_TOKENS["triage"])
        response_text = await self._sample(TRIAGE_SYSTEM_PROMPT, prompt, max_tokens=max_tokens, layer="triage")
        return self._parse_json(response_text)

    async def evaluate_chain(self, findings: list[Finding], rubric: str) -> dict:
        from prowl.triage.prompts import CHAIN_SYSTEM_PROMPT, build_chain_prompt
        prompt = build_chain_prompt(findings, rubric)
        max_tokens = self._layer_max_tokens("triage", self._DEFAULT_MAX_TOKENS["triage"])
        response_text = await self._sample(CHAIN_SYSTEM_PROMPT, prompt, max_tokens=max_tokens, layer="triage")
        return self._parse_json(response_text)

    async def generate_patch(self, context: ExploitContext, poc_code: str) -> str:
        from prowl.validation.prompts import PATCH_SYSTEM_PROMPT, build_patch_prompt
        prompt = build_patch_prompt(context, poc_code)
        max_tokens = self._layer_max_tokens("validation", self._DEFAULT_MAX_TOKENS["validation"])
        response_text = await self._sample(PATCH_SYSTEM_PROMPT, prompt, max_tokens=max_tokens, layer="validation")
        return response_text

    async def batch_triage(self, contexts: list[FindingContext]) -> list[dict]:
        from prowl.triage.prompts import BATCH_TRIAGE_SYSTEM_PROMPT, build_batch_triage_prompt
        prompt = build_batch_triage_prompt(contexts)
        max_tokens = self._layer_max_tokens("triage", self._DEFAULT_MAX_TOKENS["triage"])
        response_text = await self._sample(BATCH_TRIAGE_SYSTEM_PROMPT, prompt, max_tokens=max_tokens, layer="triage")
        return self._parse_json_list(response_text)

    # --- Response parsing ---

    @staticmethod
    def _extract_json_text(text: str) -> str:
        """Extract JSON from LLM response, stripping markdown fences.

        Prefers explicitly-tagged ```json blocks. Falls back to untagged
        fences whose body looks like JSON. Skips fences tagged with other
        languages (c, python, js, ...) so an inline code snippet in the
        model's prose reasoning doesn't hijack the extraction.
        """
        import re
        text = text.strip()
        # 1. Prefer the last explicitly-tagged ```json block (the model
        #    sometimes shows an example schema before the final answer).
        json_blocks = re.findall(r"```json\s*\n?(.*?)```", text, re.DOTALL)
        if json_blocks:
            return json_blocks[-1].strip()
        # 2. Fall back: scan every fenced block, skip ones tagged with a
        #    non-json language, and pick the last one whose body starts
        #    with { or [.
        candidate: str | None = None
        for m in re.finditer(r"```([a-zA-Z0-9_+\-]*)\s*\n?(.*?)```", text, re.DOTALL):
            tag = m.group(1).strip().lower()
            body = m.group(2).strip()
            if tag and tag != "json":
                continue
            if body.startswith("{") or body.startswith("["):
                candidate = body
        if candidate is not None:
            return candidate
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
        """Find the best top-level balanced { ... } in text.

        Returns the *largest* top-level balanced object (ties broken by
        last-occurrence). This is more robust than picking the first ``{``
        when the model writes prose containing inline code snippets like
        ``QUIC_CONN_ID rscid = { 0 };`` before the actual JSON answer.
        """
        candidates: list[str] = []
        depth = 0
        in_str = False
        start = -1
        i = 0
        while i < len(text):
            ch = text[i]
            if in_str:
                if ch == '\\':
                    i += 2
                    continue
                if ch == '"':
                    in_str = False
            else:
                if ch == '"':
                    in_str = True
                elif ch == '{':
                    if depth == 0:
                        start = i
                    depth += 1
                elif ch == '}':
                    if depth > 0:
                        depth -= 1
                        if depth == 0 and start >= 0:
                            candidates.append(text[start:i + 1])
                            start = -1
            i += 1
        if not candidates:
            # Fall back to any unbalanced fragment from the first '{' so
            # json.loads still produces a useful error message.
            first = text.find('{')
            return text[first:] if first >= 0 else text
        # Prefer the largest candidate; on ties keep the last occurrence
        # (max() with a stable key preserves the *first* max — flip via
        # reversed enumeration to get the last).
        return max(candidates, key=len)

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

    # Map LLM-invented category labels onto SignalCategory values.
    # The model often writes classic CWE-style labels (integer_overflow,
    # buffer_overflow, weak_algorithm, ...) that aren't in our enum.
    _CATEGORY_ALIASES = {
        # Memory-safety family -> memory
        "integer_overflow": "memory",
        "integer_underflow": "memory",
        "buffer_overflow": "memory",
        "buffer_overread": "memory",
        "buffer_over_read": "memory",
        "out_of_bounds": "memory",
        "oob_read": "memory",
        "oob_write": "memory",
        "use_after_free": "memory",
        "uaf": "memory",
        "double_free": "memory",
        "memory_leak": "memory",
        "uninitialized": "memory",
        "uninitialized_memory": "memory",
        "null_pointer": "memory",
        "null_dereference": "memory",
        "format_string": "memory",
        "stack_overflow": "memory",
        "heap_overflow": "memory",
        "type_confusion": "memory",
        # Crypto family -> crypto
        "weak_algorithm": "crypto",
        "weak_crypto": "crypto",
        "weak_cipher": "crypto",
        "side_channel": "crypto",
        "timing_attack": "crypto",
        "padding_oracle": "crypto",
        "insecure_random": "crypto",
        # Injection family -> injection
        "sql_injection": "injection",
        "sqli": "injection",
        "xss": "injection",
        "cross_site_scripting": "injection",
        "command_injection": "injection",
        "code_injection": "injection",
        "ldap_injection": "injection",
        "log_injection": "injection",
        # Input-validation family -> input
        "path_traversal": "input",
        "directory_traversal": "input",
        "ssrf": "input",
        "xxe": "input",
        "deserialization": "input",
        "open_redirect": "input",
        # Concurrency family -> concurrency
        "race_condition": "concurrency",
        "toctou": "concurrency",
        "data_race": "concurrency",
        # Auth family -> auth
        "authentication": "auth",
        "auth_bypass": "auth",
        "session_fixation": "auth",
        "csrf": "auth",
        # Privilege family -> privilege
        "authorization": "privilege",
        "broken_access_control": "privilege",
        "privilege_escalation": "privilege",
        # Data-access family -> data_access
        "idor": "data_access",
        "info_disclosure": "data_access",
        "information_disclosure": "data_access",
        "sensitive_data_exposure": "data_access",
    }

    @classmethod
    def _coerce_category(cls, value: Any) -> Any:
        """Map LLM-invented category labels onto SignalCategory enum values."""
        if not isinstance(value, str):
            return value
        normalized = value.strip().lower().replace("-", "_").replace(" ", "_")
        # Strip a few leading qualifiers the model sometimes adds
        for prefix in ("vuln_", "vulnerability_"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix):]
        return cls._CATEGORY_ALIASES.get(normalized, normalized)

    @classmethod
    def _normalize_hypothesis_fields(cls, data: dict) -> dict:
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
                # Coerce LLM-invented category labels to canonical enum values
                if "category" in hyp:
                    hyp["category"] = cls._coerce_category(hyp["category"])
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

