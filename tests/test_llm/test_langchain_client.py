"""Tests for the LangChain LLM client."""
from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from argus.config import LLMConfig, LLMLayerConfig
from argus.llm.langchain_client import LangChainClient


@pytest.fixture
def default_config():
    return LLMConfig()


@pytest.fixture
def multi_model_config():
    return LLMConfig(
        provider="openai",
        model="gpt-4o",
        hypothesis=LLMLayerConfig(model="gpt-4o-mini"),
        triage=LLMLayerConfig(provider="anthropic", model="claude-sonnet-4-20250514"),
    )


class TestCheckSession:
    def test_raises_without_api_key(self, default_config):
        client = LangChainClient(default_config)
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="ANTHROPIC_API_KEY"):
                client.check_session()

    def test_passes_with_api_key(self, default_config):
        client = LangChainClient(default_config)
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            client.check_session()

    def test_ollama_skips_key_check(self):
        config = LLMConfig(provider="ollama", model="llama3")
        client = LangChainClient(config)
        with patch.dict(os.environ, {}, clear=True):
            client.check_session()

    def test_custom_api_key_env(self):
        config = LLMConfig(provider="openai", api_key_env="MY_CUSTOM_KEY")
        client = LangChainClient(config)
        with patch.dict(os.environ, {"MY_CUSTOM_KEY": "test"}):
            client.check_session()
        with patch.dict(os.environ, {}, clear=True):
            with pytest.raises(RuntimeError, match="MY_CUSTOM_KEY"):
                client.check_session()


class TestCreateModel:
    def test_openai_provider(self):
        config = LLMConfig(provider="openai", model="gpt-4o")
        client = LangChainClient(config)
        mock_cls = MagicMock()
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test"}):
            with patch.dict("sys.modules", {"langchain_openai": MagicMock(ChatOpenAI=mock_cls)}):
                client._get_model("default")
                mock_cls.assert_called_once()
                call_kwargs = mock_cls.call_args[1]
                assert call_kwargs["model"] == "gpt-4o"
                assert call_kwargs["temperature"] == 0.0

    def test_anthropic_provider(self):
        config = LLMConfig(provider="anthropic", model="claude-sonnet-4-20250514")
        client = LangChainClient(config)
        mock_cls = MagicMock()
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test"}):
            with patch.dict("sys.modules", {"langchain_anthropic": MagicMock(ChatAnthropic=mock_cls)}):
                client._get_model("default")
                mock_cls.assert_called_once()
                call_kwargs = mock_cls.call_args[1]
                assert call_kwargs["model"] == "claude-sonnet-4-20250514"

    def test_google_provider(self):
        config = LLMConfig(provider="google", model="gemini-pro")
        client = LangChainClient(config)
        mock_cls = MagicMock()
        with patch.dict(os.environ, {"GOOGLE_API_KEY": "test"}):
            with patch.dict("sys.modules", {"langchain_google_genai": MagicMock(ChatGoogleGenerativeAI=mock_cls)}):
                client._get_model("default")
                mock_cls.assert_called_once()

    def test_ollama_provider(self):
        config = LLMConfig(provider="ollama", model="llama3", base_url="http://localhost:11434")
        client = LangChainClient(config)
        mock_cls = MagicMock()
        with patch.dict("sys.modules", {"langchain_ollama": MagicMock(ChatOllama=mock_cls)}):
            client._get_model("default")
            mock_cls.assert_called_once()
            call_kwargs = mock_cls.call_args[1]
            assert call_kwargs["base_url"] == "http://localhost:11434"

    def test_unknown_provider_raises(self):
        config = LLMConfig(provider="unknown", model="x")
        client = LangChainClient(config)
        with pytest.raises(ValueError, match="Unknown LLM provider"):
            client._get_model("default")

    def test_model_cached_per_layer(self):
        config = LLMConfig(provider="openai", model="gpt-4o")
        client = LangChainClient(config)
        mock_cls = MagicMock()
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test"}):
            with patch.dict("sys.modules", {"langchain_openai": MagicMock(ChatOpenAI=mock_cls)}):
                m1 = client._get_model("hypothesis")
                m2 = client._get_model("hypothesis")
                assert m1 is m2
                assert mock_cls.call_count == 1


class TestPerLayerRouting:
    def test_layer_override_model(self, multi_model_config):
        client = LangChainClient(multi_model_config)
        mock_openai = MagicMock()
        mock_anthropic = MagicMock()
        with patch.dict(os.environ, {"OPENAI_API_KEY": "test", "ANTHROPIC_API_KEY": "test"}):
            with patch.dict("sys.modules", {
                "langchain_openai": MagicMock(ChatOpenAI=mock_openai),
                "langchain_anthropic": MagicMock(ChatAnthropic=mock_anthropic),
            }):
                client._get_model("hypothesis")
                assert mock_openai.call_args[1]["model"] == "gpt-4o-mini"

                client._get_model("triage")
                mock_anthropic.assert_called_once()
                assert mock_anthropic.call_args[1]["model"] == "claude-sonnet-4-20250514"


class TestSample:
    @pytest.mark.asyncio
    async def test_sample_calls_ainvoke(self, default_config):
        client = LangChainClient(default_config)
        mock_model = AsyncMock()
        mock_response = MagicMock()
        mock_response.content = '{"test": true}'
        mock_model.ainvoke.return_value = mock_response
        client._models["default"] = mock_model

        result = await client._sample("system", "user", max_tokens=100)
        assert result == '{"test": true}'
        mock_model.ainvoke.assert_called_once()
        messages = mock_model.ainvoke.call_args[0][0]
        assert len(messages) == 2
        assert messages[0].content == "system"
        assert messages[1].content == "user"

    @pytest.mark.asyncio
    async def test_sample_handles_list_content(self, default_config):
        client = LangChainClient(default_config)
        mock_model = AsyncMock()
        mock_response = MagicMock()
        mock_response.content = [{"text": "hello "}, {"text": "world"}]
        mock_model.ainvoke.return_value = mock_response
        client._models["default"] = mock_model

        result = await client._sample("system", "user")
        assert result == "hello world"


class TestParsing:
    def test_parse_json(self, default_config):
        client = LangChainClient(default_config)
        result = client._parse_json('{"classification": "exploitable"}')
        assert result == {"classification": "exploitable"}

    def test_parse_json_from_markdown(self, default_config):
        client = LangChainClient(default_config)
        text = 'Here is the result:\n{"classification": "exploitable"}'
        result = client._parse_json(text)
        assert result["classification"] == "exploitable"

    def test_parse_json_list(self, default_config):
        client = LangChainClient(default_config)
        result = client._parse_json_list('[{"a": 1}, {"a": 2}]')
        assert len(result) == 2

    def test_parse_response_with_pydantic(self, default_config):
        from argus.models.hypothesis import HypothesisResponse
        client = LangChainClient(default_config)
        text = '{"hypotheses": [], "analysis_notes": "none"}'
        result = client._parse_response(text, HypothesisResponse)
        assert isinstance(result, HypothesisResponse)
        assert result.hypotheses == []

    def test_parse_json_unquoted_keys(self, default_config):
        client = LangChainClient(default_config)
        text = '{classification: "exploitable", severity: "high", confidence: 0.9}'
        result = client._parse_json(text)
        assert result["classification"] == "exploitable"
        assert result["severity"] == "high"
        assert result["confidence"] == 0.9

    def test_parse_json_trailing_comma(self, default_config):
        client = LangChainClient(default_config)
        text = '{"classification": "exploitable", "severity": "high",}'
        result = client._parse_json(text)
        assert result["classification"] == "exploitable"

    def test_parse_json_unescaped_newlines_in_string(self, default_config):
        """LLM puts raw newlines inside JSON string values (e.g. code fields)."""
        client = LangChainClient(default_config)
        text = '{"code": "#include <stdio.h>\nint main() {\n  return 0;\n}", "language": "c"}'
        result = client._parse_json(text)
        assert result["language"] == "c"
        assert "stdio" in result["code"]

    def test_parse_json_unescaped_control_chars(self, default_config):
        """LLM embeds tab and other control chars in string values."""
        client = LangChainClient(default_config)
        text = '{"code": "line1\\tindented", "ok": true}'
        result = client._parse_json(text)
        assert result["ok"] is True

    def test_parse_json_code_fences_wrapping(self, default_config):
        client = LangChainClient(default_config)
        text = '```json\n{classification: "exploitable", severity: "high"}\n```'
        result = client._parse_json(text)
        assert result["classification"] == "exploitable"

    def test_parse_json_prose_before_json(self, default_config):
        client = LangChainClient(default_config)
        text = 'Here is my analysis:\n\n{"classification": "false_positive", "confidence": 0.3}'
        result = client._parse_json(text)
        assert result["classification"] == "false_positive"

    def test_parse_json_prose_after_json(self, default_config):
        """Extra text after the JSON object should be ignored."""
        client = LangChainClient(default_config)
        text = '{"classification": "exploitable"}\n\nLet me know if you need more details.'
        result = client._parse_json(text)
        assert result["classification"] == "exploitable"

    def test_parse_json_list_unquoted_keys(self, default_config):
        client = LangChainClient(default_config)
        text = '[{title: "sqli", classification: "exploitable"}, {title: "xss", classification: "mitigated"}]'
        result = client._parse_json_list(text)
        assert len(result) == 2
        assert result[0]["title"] == "sqli"

    def test_parse_json_complex_poc_code(self, default_config):
        """Realistic PoC response with embedded C code containing special chars."""
        client = LangChainClient(default_config)
        text = '''{
            "code": "#include <stdio.h>\\nint main() {\\n  char buf[10];\\n  memcpy(buf, \\"AAAA\\", 4);\\n  return 0;\\n}",
            "language": "c",
            "description": "Buffer overflow PoC"
        }'''
        result = client._parse_json(text)
        assert result["language"] == "c"
        assert result["description"] == "Buffer overflow PoC"

    def test_fix_json_unquoted_nested(self, default_config):
        client = LangChainClient(default_config)
        text = '{classification: "exploitable", mitigations_found: ["none"], reasoning: "vuln is real"}'
        result = client._parse_json(text)
        assert result["classification"] == "exploitable"
        assert result["mitigations_found"] == ["none"]

    def test_find_json_object_with_trailing_text(self, default_config):
        """_find_json_object should extract balanced braces, ignoring trailing prose."""
        text = 'Result: {"a": 1, "b": {"c": 2}} some trailing stuff'
        result = LangChainClient._find_json_object(text)
        assert result == '{"a": 1, "b": {"c": 2}}'

    def test_find_json_array_with_trailing_text(self, default_config):
        text = 'Here: [{"a": 1}, {"b": 2}] done'
        result = LangChainClient._find_json_array(text)
        assert result == '[{"a": 1}, {"b": 2}]'

    def test_parse_json_single_quoted_keys(self, default_config):
        """LLM returns JSON with single-quoted keys (Python dict style)."""
        client = LangChainClient(default_config)
        text = "{'classification': 'exploitable', 'severity': 'high', 'confidence': 0.9}"
        result = client._parse_json(text)
        assert result["classification"] == "exploitable"
        assert result["severity"] == "high"

    def test_parse_json_single_quoted_keys_multiline(self, default_config):
        client = LangChainClient(default_config)
        text = "{\n    'classification': 'exploitable',\n    'reasoning': 'buffer overflow'\n}"
        result = client._parse_json(text)
        assert result["classification"] == "exploitable"
        assert result["reasoning"] == "buffer overflow"

    def test_parse_json_mixed_quotes(self, default_config):
        """LLM mixes single and double quotes."""
        client = LangChainClient(default_config)
        text = """{'classification': "exploitable", "severity": 'high'}"""
        result = client._parse_json(text)
        assert result["classification"] == "exploitable"
        assert result["severity"] == "high"

    # --- PoC response parsing ---

    def test_parse_poc_response_fenced_block(self, default_config):
        """PoC with code in fenced block + JSON metadata."""
        client = LangChainClient(default_config)
        text = '''```c
#include <stdio.h>
int main() {
    printf("hello %s", user_input);
    return 0;
}
```
{"language": "c", "description": "format string PoC", "setup_instructions": "compile with gcc"}'''
        result = client._parse_poc_response(text)
        assert result["language"] == "c"
        assert result["description"] == "format string PoC"
        assert '#include <stdio.h>' in result["code"]
        assert 'printf("hello %s"' in result["code"]

    def test_parse_poc_response_fenced_block_with_prose(self, default_config):
        """PoC with prose before the code block."""
        client = LangChainClient(default_config)
        text = '''Here's a PoC that demonstrates the buffer overflow:

```python
import struct
payload = b"A" * 256 + struct.pack("<I", 0xdeadbeef)
print(payload)
```
{"language": "python", "description": "buffer overflow PoC"}'''
        result = client._parse_poc_response(text)
        assert result["language"] == "python"
        assert "struct.pack" in result["code"]

    def test_parse_poc_response_fenced_block_no_metadata(self, default_config):
        """PoC with code block but no JSON metadata after it."""
        client = LangChainClient(default_config)
        text = '''```c
int main() { return 0; }
```'''
        result = client._parse_poc_response(text)
        assert result["code"] == "int main() { return 0; }"
        assert result["language"] == "c"

    def test_parse_poc_response_fallback_to_json(self, default_config):
        """PoC in old JSON format still works as fallback."""
        client = LangChainClient(default_config)
        text = '{"code": "print(1)", "language": "python", "description": "test"}'
        result = client._parse_poc_response(text)
        assert result["code"] == "print(1)"
        assert result["language"] == "python"

    def test_parse_poc_response_complex_c_code(self, default_config):
        """C code with quotes, newlines, special chars in fenced block."""
        client = LangChainClient(default_config)
        text = '''```c
#include <stdio.h>
#include <string.h>
int main() {
    char buf[10];
    char *input = "AAAAAAAAAAAAAAAA"; // overflow
    strcpy(buf, input);
    printf("buf = %s\\n", buf);
    return 0;
}
```
{"language": "c", "description": "stack buffer overflow via strcpy"}'''
        result = client._parse_poc_response(text)
        assert result["language"] == "c"
        assert "strcpy(buf, input)" in result["code"]
        assert '#include <string.h>' in result["code"]

    # --- Hypothesis field normalization ---

    def test_normalize_hypothesis_single_object(self, default_config):
        """LLM returns a single hypothesis without wrapping in a list."""
        client = LangChainClient(default_config)
        data = {"title": "sqli", "description": "d", "severity": "high",
                "category": "data_access", "confidence": 0.8}
        normalized = client._normalize_hypothesis_fields(data)
        assert "hypotheses" in normalized
        assert len(normalized["hypotheses"]) == 1

    def test_normalize_hypothesis_list_at_top(self, default_config):
        """LLM returns a list instead of {"hypotheses": [...]}}."""
        client = LangChainClient(default_config)
        data = [{"title": "sqli", "description": "d", "severity": "high",
                 "category": "data_access", "confidence": 0.8}]
        normalized = client._normalize_hypothesis_fields(data)
        assert "hypotheses" in normalized

    def test_normalize_hypothesis_field_aliases(self, default_config):
        """LLM uses vuln_type instead of category, confidence_score instead of confidence."""
        client = LangChainClient(default_config)
        data = {"hypotheses": [{"title": "t", "description": "d", "severity": "high",
                                "vuln_type": "memory", "confidence_score": 0.9,
                                "attack_path": "via input"}]}
        normalized = client._normalize_hypothesis_fields(data)
        hyp = normalized["hypotheses"][0]
        assert hyp["category"] == "memory"
        assert hyp["confidence"] == 0.9
        assert hyp["attack_scenario"] == "via input"


class TestFactory:
    def test_create_llm_client_returns_langchain(self):
        from argus.config import ArgusConfig
        from argus.llm.sampling import create_llm_client
        config = ArgusConfig()
        client = create_llm_client(config)
        assert isinstance(client, LangChainClient)
