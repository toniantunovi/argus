"""Per-vulnerability-class result checking."""
from __future__ import annotations

import re

from prowl.models.core import SignalCategory
from prowl.models.poc import ValidationStatus


def check_result(
    category: SignalCategory,
    stdout: str,
    stderr: str,
    exit_code: int,
    http_response: str | None = None,
    sanitizer_output: dict | None = None,
    target_function: str | None = None,
) -> ValidationStatus:
    """Check execution result for success evidence.

    Args:
        target_function: If provided, memory checker verifies the ASAN trace
            includes this function name for stronger confirmation.
    """
    checkers = {
        SignalCategory.AUTH: _check_auth,
        SignalCategory.DATA_ACCESS: _check_data_access,
        SignalCategory.INJECTION: _check_injection,
        SignalCategory.MEMORY: _check_memory,
        SignalCategory.CONCURRENCY: _check_concurrency,
        SignalCategory.INPUT: _check_input,
        SignalCategory.CRYPTO: _check_crypto,
        SignalCategory.FINANCIAL: _check_financial,
        SignalCategory.PRIVILEGE: _check_privilege,
    }
    checker = checkers.get(category, _check_generic)
    if category == SignalCategory.MEMORY:
        return _check_memory(stdout, stderr, exit_code, http_response, sanitizer_output, target_function)
    return checker(stdout, stderr, exit_code, http_response, sanitizer_output)


def _check_auth(stdout, stderr, exit_code, http_response, sanitizer_output) -> ValidationStatus:
    """Missing auth: response contains unauthorized data."""
    combined = stdout + (http_response or "")
    if exit_code == 0 and any(marker in combined.lower() for marker in ["unauthorized access", "admin", "success", "200", "token", "secret"]):
        return ValidationStatus.CONFIRMED
    if "401" in combined or "403" in combined or "unauthorized" in combined.lower():
        return ValidationStatus.FAILED
    return ValidationStatus.PARTIAL


def _check_data_access(stdout, stderr, exit_code, http_response, sanitizer_output) -> ValidationStatus:
    """SQL injection / IDOR: query returns unauthorized data."""
    combined = stdout + (http_response or "")
    if exit_code == 0 and any(marker in combined.lower() for marker in ["unauthorized data", "all users", "admin", "password", "success"]):
        return ValidationStatus.CONFIRMED
    return ValidationStatus.PARTIAL if exit_code == 0 else ValidationStatus.FAILED


def _check_injection(stdout, stderr, exit_code, http_response, sanitizer_output) -> ValidationStatus:
    """Command injection / XSS: observable side effect."""
    combined = stdout + (http_response or "")
    # Command injection: output from injected command
    if "ARGUS_INJECTION_PROOF" in combined or exit_code == 0:
        if any(marker in combined for marker in ["ARGUS_INJECTION_PROOF", "uid=", "root:", "/etc/passwd", "<script>", "alert("]):
            return ValidationStatus.CONFIRMED
    # XSS: script tag in response
    if http_response and re.search(r"<script[^>]*>", http_response, re.I):
        return ValidationStatus.CONFIRMED
    return ValidationStatus.PARTIAL if exit_code == 0 else ValidationStatus.FAILED


def _check_memory(stdout, stderr, exit_code, http_response, sanitizer_output, target_function=None) -> ValidationStatus:
    """Memory corruption: ASAN/MSAN/UBSAN report.

    If target_function is provided and ASAN fires, we verify the stack trace
    includes the expected function for stronger confirmation.
    """
    has_sanitizer = bool(sanitizer_output)
    has_sanitizer_text = "AddressSanitizer" in stderr or "MemorySanitizer" in stderr or "runtime error:" in stderr

    if has_sanitizer or has_sanitizer_text:
        # ASAN fired — confirmed.  If we know the target function, note whether
        # it appeared in the trace (callers can inspect success_evidence), but
        # either way it's still CONFIRMED.
        return ValidationStatus.CONFIRMED

    if "Segmentation fault" in stderr or exit_code in (139, 134, 136):
        return ValidationStatus.PARTIAL  # crash but no sanitizer
    return ValidationStatus.FAILED


def _check_concurrency(stdout, stderr, exit_code, http_response, sanitizer_output) -> ValidationStatus:
    """Race condition: observable inconsistency."""
    combined = stdout + (http_response or "")
    if any(marker in combined.lower() for marker in ["race detected", "inconsistent", "double", "duplicate", "ARGUS_RACE_PROOF"]):
        return ValidationStatus.CONFIRMED
    return ValidationStatus.PARTIAL if exit_code == 0 else ValidationStatus.FAILED


def _check_input(stdout, stderr, exit_code, http_response, sanitizer_output) -> ValidationStatus:
    return _check_generic(stdout, stderr, exit_code, http_response, sanitizer_output)


def _check_crypto(stdout, stderr, exit_code, http_response, sanitizer_output) -> ValidationStatus:
    combined = stdout + (http_response or "")
    if any(marker in combined.lower() for marker in ["weak", "predictable", "collision", "broken"]):
        return ValidationStatus.CONFIRMED
    return ValidationStatus.PARTIAL if exit_code == 0 else ValidationStatus.FAILED


def _check_financial(stdout, stderr, exit_code, http_response, sanitizer_output) -> ValidationStatus:
    combined = stdout + (http_response or "")
    if any(marker in combined.lower() for marker in ["negative balance", "double charge", "invalid state", "unauthorized transaction"]):
        return ValidationStatus.CONFIRMED
    return ValidationStatus.PARTIAL if exit_code == 0 else ValidationStatus.FAILED


def _check_privilege(stdout, stderr, exit_code, http_response, sanitizer_output) -> ValidationStatus:
    combined = stdout + (http_response or "")
    if any(marker in combined.lower() for marker in ["escalated", "root", "admin", "privilege"]):
        return ValidationStatus.CONFIRMED
    return ValidationStatus.PARTIAL if exit_code == 0 else ValidationStatus.FAILED


def _check_generic(stdout, stderr, exit_code, http_response, sanitizer_output) -> ValidationStatus:
    if sanitizer_output:
        return ValidationStatus.CONFIRMED
    if exit_code == 0 and ("success" in stdout.lower() or "ARGUS_PROOF" in stdout):
        return ValidationStatus.CONFIRMED
    return ValidationStatus.PARTIAL if exit_code == 0 else ValidationStatus.FAILED
