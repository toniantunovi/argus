"""Retry logic for LLM calls."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Callable, TypeVar

logger = logging.getLogger(__name__)
T = TypeVar("T")

class RetryConfig:
    def __init__(self, max_retries_malformed: int = 1, max_retries_timeout: int = 3, base_delay: float = 1.0):
        self.max_retries_malformed = max_retries_malformed
        self.max_retries_timeout = max_retries_timeout
        self.base_delay = base_delay

async def retry_with_backoff(
    func: Callable[..., Any],
    *args: Any,
    config: RetryConfig | None = None,
    on_malformed: Callable[[str], str] | None = None,
    **kwargs: Any,
) -> Any:
    """Retry an async function with exponential backoff for timeouts and one retry for malformed output."""
    if config is None:
        config = RetryConfig()

    last_error = None
    for attempt in range(config.max_retries_timeout + 1):
        try:
            result = await func(*args, **kwargs)
            return result
        except (TimeoutError, asyncio.TimeoutError, ConnectionError) as e:
            last_error = e
            if attempt < config.max_retries_timeout:
                delay = config.base_delay * (2 ** attempt)
                logger.warning(f"Timeout/connection error (attempt {attempt + 1}), retrying in {delay}s: {e}")
                await asyncio.sleep(delay)
            else:
                raise
        except ValueError as e:
            # Malformed output
            if on_malformed and attempt < config.max_retries_malformed:
                logger.warning(f"Malformed output (attempt {attempt + 1}): {e}")
                # Append error context for retry
                if "kwargs" in kwargs:
                    kwargs["error_context"] = str(e)
                raise  # Let caller handle retry with modified context
            raise
    raise last_error or RuntimeError("Retry exhausted")
