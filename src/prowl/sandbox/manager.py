"""Sandbox container lifecycle management.

This module provides the SandboxManager protocol used by the validation engine.
The actual sandbox execution is handled by ClawValidationBackend, which builds
the real target project inside Docker and runs it with crafted inputs — no
standalone PoC code is ever generated or executed.
"""
from __future__ import annotations

from typing import Protocol


class SandboxManager(Protocol):
    """Protocol for sandbox management — allows mocking in tests.

    The concrete implementation lives in ClawValidationBackend which manages
    Docker containers directly.  This protocol exists so the pipeline can
    accept a mock during testing.
    """
    ...
