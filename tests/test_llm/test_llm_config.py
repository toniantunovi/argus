"""Tests for LLM configuration models."""
from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest
import yaml

from argus.config import ArgusConfig, LLMConfig, LLMLayerConfig, load_config


class TestLLMConfigDefaults:
    def test_default_provider(self):
        config = LLMConfig()
        assert config.provider == "anthropic"
        assert config.model == "claude-opus-4-6"
        assert config.temperature == 0.0
        assert config.api_key_env is None
        assert config.base_url is None

    def test_layer_defaults_are_none(self):
        config = LLMConfig()
        assert config.hypothesis.provider is None
        assert config.hypothesis.model is None
        assert config.triage.provider is None
        assert config.validation.provider is None


class TestArgusConfigWithLLM:
    def test_default_argus_config_has_llm(self):
        config = ArgusConfig()
        assert isinstance(config.llm, LLMConfig)
        assert config.llm.provider == "anthropic"

    def test_load_config_without_llm_section(self, tmp_path):
        (tmp_path / "argus.yml").write_text("scan:\n  project_type: auto\n")
        config = load_config(tmp_path)
        assert isinstance(config.llm, LLMConfig)
        assert config.llm.provider == "anthropic"

    def test_load_config_with_llm_section(self, tmp_path):
        content = dedent("""\
            llm:
              provider: openai
              model: gpt-4o
              temperature: 0.2
              hypothesis:
                model: gpt-4o-mini
        """)
        (tmp_path / "argus.yml").write_text(content)
        config = load_config(tmp_path)
        assert config.llm.provider == "openai"
        assert config.llm.model == "gpt-4o"
        assert config.llm.temperature == 0.2
        assert config.llm.hypothesis.model == "gpt-4o-mini"
        assert config.llm.triage.model is None

    def test_load_config_with_ollama(self, tmp_path):
        content = dedent("""\
            llm:
              provider: ollama
              model: llama3
              base_url: http://localhost:11434
        """)
        (tmp_path / "argus.yml").write_text(content)
        config = load_config(tmp_path)
        assert config.llm.provider == "ollama"
        assert config.llm.base_url == "http://localhost:11434"
