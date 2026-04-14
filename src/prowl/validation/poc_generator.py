"""PoC generation helpers."""
from __future__ import annotations

from prowl.models.poc import PoC


def format_poc_for_execution(poc: PoC, language: str) -> str:
    """Format PoC code for execution in sandbox."""
    if language == "python" and "if __name__" not in poc.code:
        return poc.code + "\n\nif __name__ == '__main__':\n    main()\n"
    return poc.code
