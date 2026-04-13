"""Pydantic -> JSON schema for LLM prompts and response validation."""
from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel


def model_to_schema_str(model_class: type[BaseModel]) -> str:
    """Generate JSON schema string for inclusion in LLM prompts."""
    schema = model_class.model_json_schema()
    return json.dumps(schema, indent=2)

def validate_response(text: str, model_class: type[BaseModel]) -> tuple[Any | None, str | None]:
    """Validate LLM response against a Pydantic model.
    Returns (parsed_model, None) on success or (None, error_message) on failure.
    """
    text = _extract_json(text)
    try:
        return model_class.model_validate_json(text), None
    except Exception as e:
        return None, str(e)

def _extract_json(text: str) -> str:
    """Extract JSON from LLM response text."""
    text = text.strip()
    # Remove markdown code blocks
    if text.startswith("```"):
        lines = text.split("\n")
        json_lines = []
        in_block = False
        for line in lines:
            if line.strip().startswith("```") and not in_block:
                in_block = True
                continue
            elif line.strip() == "```" and in_block:
                break
            elif in_block:
                json_lines.append(line)
        if json_lines:
            text = "\n".join(json_lines)

    # Find first { or [
    for i, c in enumerate(text):
        if c in ('{', '['):
            text = text[i:]
            break

    return text
