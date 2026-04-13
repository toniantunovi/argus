"""YAML rubric loading with built-in + custom merge."""
from __future__ import annotations

from pathlib import Path

import yaml

from argus.models.core import RubricTier, SignalCategory

RUBRIC_DIR = Path(__file__).parent


def load_rubric(layer: str, categories: list[SignalCategory], tier: RubricTier = RubricTier.STANDARD) -> str:
    """Load and format rubric for given layer and categories.

    Args:
        layer: "detection", "triage", or "exploit"
        categories: signal categories to load rubrics for
        tier: rubric tier (conservative/standard/aggressive)

    Returns:
        Formatted rubric text for inclusion in LLM prompt.
    """
    rubric_parts = []
    subdir = RUBRIC_DIR / layer

    for category in categories:
        cat_name = category.value if isinstance(category, SignalCategory) else category
        rubric_file = subdir / f"{cat_name}.yml"
        if rubric_file.exists():
            with open(rubric_file) as f:
                data = yaml.safe_load(f) or {}
            rules = data.get("detection_rules", data.get("triage_rules", data.get("exploit_rules", [])))
            rubric_parts.append(f"## {cat_name.upper()} Category\n")
            for rule in rules:
                name = rule.get("name", "unnamed")
                instruction = rule.get("instruction", "")
                # Apply tier-based filtering
                rule_tier = rule.get("min_tier", "conservative")
                if _tier_passes(rule_tier, tier):
                    rubric_parts.append(f"### {name}\n{instruction}\n")

    if not rubric_parts:
        return _get_default_rubric(layer, categories, tier)

    return "\n".join(rubric_parts)


def load_custom_rubrics(project_root: Path, layer: str, categories: list[SignalCategory]) -> str:
    """Load custom rubrics from .argus/rubrics/ and merge with built-in."""
    custom_dir = project_root / ".argus" / "rubrics"
    if not custom_dir.exists():
        return ""
    parts = []
    for category in categories:
        cat_name = category.value if isinstance(category, SignalCategory) else category
        custom_file = custom_dir / f"{cat_name}.yml"
        if custom_file.exists():
            with open(custom_file) as f:
                data = yaml.safe_load(f) or {}
            rules = data.get("detection_rules", [])
            for rule in rules:
                parts.append(f"### [Custom] {rule.get('name', 'unnamed')}\n{rule.get('instruction', '')}\n")
    return "\n".join(parts)


def _tier_passes(rule_tier: str, current_tier: RubricTier) -> bool:
    order = {"conservative": 0, "standard": 1, "aggressive": 2}
    return order.get(current_tier.value, 1) >= order.get(rule_tier, 0)


def _get_default_rubric(layer: str, categories: list[SignalCategory], tier: RubricTier) -> str:
    """Generate a default rubric when no YAML file exists."""
    default_detection = {
        SignalCategory.AUTH: (
            "## AUTH Detection Rules\n"
            "### authentication_bypass\n"
            "Look for missing or weak authentication checks. Check for functions that access "
            "protected resources without verifying user identity. Flag hardcoded credentials, "
            "default passwords, and authentication logic that can be skipped.\n\n"
            "### session_management\n"
            "Check for weak session token generation, missing session expiry, session fixation "
            "vulnerabilities, and insecure session storage.\n\n"
            "### authorization_flaw\n"
            "Identify missing authorization checks, especially in functions that modify data "
            "or access other users' resources. Look for IDOR patterns where user-supplied IDs "
            "are used without ownership validation.\n"
        ),
        SignalCategory.DATA_ACCESS: (
            "## DATA_ACCESS Detection Rules\n"
            "### insecure_data_exposure\n"
            "Look for sensitive data returned in API responses without filtering. Check for "
            "logging of sensitive fields (passwords, tokens, PII). Flag missing encryption "
            "for data at rest or in transit.\n\n"
            "### mass_assignment\n"
            "Check for bulk property assignment from user input without whitelisting. Look for "
            "ORM models that accept all fields from request bodies.\n\n"
            "### path_traversal\n"
            "Identify file access operations using user-controlled paths without sanitization. "
            "Check for directory traversal sequences (../) in file operations.\n"
        ),
        SignalCategory.INPUT: (
            "## INPUT Detection Rules\n"
            "### xss\n"
            "Look for user input reflected in HTML output without escaping. Check for "
            "innerHTML assignments, document.write calls, and template literals with "
            "unescaped variables.\n\n"
            "### unsafe_deserialization\n"
            "Check for deserialization of untrusted data using pickle, yaml.load, "
            "JSON.parse with reviver, or Java ObjectInputStream without type filtering.\n\n"
            "### header_injection\n"
            "Identify user input used in HTTP headers without newline sanitization. "
            "Check for CRLF injection in redirect URLs and cookie values.\n"
        ),
        SignalCategory.CRYPTO: (
            "## CRYPTO Detection Rules\n"
            "### weak_algorithm\n"
            "Flag use of MD5, SHA1 for security purposes, DES, RC4, or ECB mode. "
            "Check for insufficient key lengths (RSA < 2048, AES < 128).\n\n"
            "### key_management\n"
            "Look for hardcoded encryption keys, keys derived from weak sources, "
            "missing key rotation, and keys stored alongside encrypted data.\n\n"
            "### random_weakness\n"
            "Check for use of non-cryptographic PRNGs (Math.random, random.random) "
            "for security-sensitive operations like token generation.\n"
        ),
        SignalCategory.FINANCIAL: (
            "## FINANCIAL Detection Rules\n"
            "### race_condition_payment\n"
            "Look for payment processing without idempotency keys. Check for "
            "double-spend vulnerabilities in balance deduction logic.\n\n"
            "### price_manipulation\n"
            "Identify client-controlled price values accepted without server-side "
            "validation. Check for discount/coupon logic bypass.\n\n"
            "### integer_overflow_currency\n"
            "Check for arithmetic operations on currency values that could overflow "
            "or lose precision due to floating point representation.\n"
        ),
        SignalCategory.PRIVILEGE: (
            "## PRIVILEGE Detection Rules\n"
            "### privilege_escalation\n"
            "Look for role checks that can be bypassed. Check for functions that "
            "change user roles or permissions without adequate authorization.\n\n"
            "### admin_bypass\n"
            "Identify admin endpoints or functions accessible without admin "
            "authentication. Check for debug/test backdoors in production code.\n\n"
            "### sandbox_escape\n"
            "Look for operations that break out of restricted execution environments. "
            "Check for file system access, network calls, or process spawning in "
            "sandboxed contexts.\n"
        ),
        SignalCategory.MEMORY: (
            "## MEMORY Detection Rules\n"
            "### buffer_overflow\n"
            "Look for fixed-size buffer operations without bounds checking. Check for "
            "strcpy, sprintf, gets, and similar unsafe C functions. Flag array indexing "
            "without bounds validation.\n\n"
            "### use_after_free\n"
            "Check for pointers used after the underlying memory has been freed. Look "
            "for dangling references in callback chains and event handlers.\n\n"
            "### integer_overflow\n"
            "Identify arithmetic operations on sizes or offsets that could wrap around. "
            "Check for unchecked multiplication used in memory allocation sizes.\n"
        ),
        SignalCategory.INJECTION: (
            "## INJECTION Detection Rules\n"
            "### sql_injection\n"
            "Look for string concatenation or formatting in SQL queries with user input. "
            "Check for raw SQL queries that bypass ORM protections.\n\n"
            "### command_injection\n"
            "Identify shell command construction using user input. Check for os.system, "
            "subprocess with shell=True, exec, eval, and backtick execution.\n\n"
            "### template_injection\n"
            "Look for server-side template rendering with user-controlled template strings. "
            "Check for Jinja2, Mako, Freemarker, and Velocity template injection.\n"
        ),
        SignalCategory.CONCURRENCY: (
            "## CONCURRENCY Detection Rules\n"
            "### race_condition\n"
            "Look for check-then-act patterns without atomic operations or locking. "
            "Check for TOCTOU vulnerabilities in file operations and permission checks.\n\n"
            "### deadlock_potential\n"
            "Identify lock acquisition in inconsistent orders. Check for nested locks "
            "that could deadlock under concurrent access.\n\n"
            "### data_race\n"
            "Look for shared mutable state accessed without synchronization. Check for "
            "global variables modified in request handlers without locks.\n"
        ),
    }

    default_triage = {
        SignalCategory.AUTH: (
            "## AUTH Triage Rules\n"
            "### verify_reachability\n"
            "Confirm the authentication bypass is reachable from an external entry point. "
            "Check if middleware or filters enforce authentication before the vulnerable code.\n\n"
            "### assess_impact\n"
            "Determine what resources become accessible if authentication is bypassed. "
            "Rate severity based on data sensitivity and action criticality.\n"
        ),
        SignalCategory.DATA_ACCESS: (
            "## DATA_ACCESS Triage Rules\n"
            "### verify_data_sensitivity\n"
            "Confirm the exposed data is actually sensitive (PII, credentials, financial). "
            "Check if the data is already public or redacted elsewhere.\n\n"
            "### check_access_controls\n"
            "Verify whether other access controls exist that prevent unauthorized access "
            "even if this specific check is missing.\n"
        ),
        SignalCategory.INPUT: (
            "## INPUT Triage Rules\n"
            "### trace_data_flow\n"
            "Follow user input from source to sink. Verify no sanitization or encoding "
            "is applied along the path.\n\n"
            "### check_content_type\n"
            "Verify the response content type allows exploitation (e.g., text/html for XSS). "
            "Check for Content-Security-Policy headers that might mitigate.\n"
        ),
        SignalCategory.CRYPTO: (
            "## CRYPTO Triage Rules\n"
            "### assess_crypto_context\n"
            "Determine if the weak crypto is used for security-critical operations or just "
            "checksums/caching. Weak hashing for cache keys is low severity.\n\n"
            "### check_key_exposure\n"
            "Verify if weak key material is actually exposed or if other controls protect it.\n"
        ),
        SignalCategory.FINANCIAL: (
            "## FINANCIAL Triage Rules\n"
            "### verify_transaction_flow\n"
            "Confirm the financial logic flaw is exploitable in a real transaction flow. "
            "Check for compensating controls like audit logs and manual review.\n\n"
            "### assess_financial_impact\n"
            "Estimate the potential financial loss from exploitation. Consider rate limiting "
            "and monitoring that might detect exploitation.\n"
        ),
        SignalCategory.PRIVILEGE: (
            "## PRIVILEGE Triage Rules\n"
            "### verify_escalation_path\n"
            "Confirm a lower-privileged user can actually reach the escalation point. "
            "Check for network-level or infrastructure-level access controls.\n\n"
            "### assess_privilege_delta\n"
            "Determine the difference in privilege between the attacker's role and the "
            "target role. Higher delta means higher severity.\n"
        ),
        SignalCategory.MEMORY: (
            "## MEMORY Triage Rules\n"
            "### check_exploit_mitigations\n"
            "Verify which exploit mitigations are enabled (ASLR, DEP, stack canaries, "
            "CFI). Assess if the vulnerability is exploitable with mitigations active.\n\n"
            "### assess_control\n"
            "Determine the degree of control an attacker has over the corrupted memory. "
            "Full control of overwritten data increases severity.\n"
        ),
        SignalCategory.INJECTION: (
            "## INJECTION Triage Rules\n"
            "### verify_injection_path\n"
            "Confirm user input reaches the injection sink without adequate sanitization. "
            "Check for WAF rules, input validation, and parameterized queries.\n\n"
            "### assess_injection_impact\n"
            "Determine what operations are possible through the injection. SQL injection "
            "with write access is more severe than read-only.\n"
        ),
        SignalCategory.CONCURRENCY: (
            "## CONCURRENCY Triage Rules\n"
            "### verify_race_window\n"
            "Confirm the race window is large enough to be exploitable. Check if the "
            "operation timing can be controlled by the attacker.\n\n"
            "### assess_race_impact\n"
            "Determine the consequence of winning the race. Privilege escalation via "
            "race condition is more severe than a benign state inconsistency.\n"
        ),
    }

    default_exploit = {
        SignalCategory.AUTH: (
            "## AUTH Exploit Rules\n"
            "### craft_bypass_request\n"
            "Construct HTTP requests that reach the protected endpoint without valid "
            "credentials. Test with missing, empty, and malformed auth tokens.\n\n"
            "### demonstrate_access\n"
            "Show that the bypass provides access to protected resources or actions. "
            "Include the response data as evidence.\n"
        ),
        SignalCategory.DATA_ACCESS: (
            "## DATA_ACCESS Exploit Rules\n"
            "### extract_sensitive_data\n"
            "Demonstrate retrieval of sensitive data through the vulnerable endpoint. "
            "Show the full request/response cycle.\n\n"
            "### prove_unauthorized_access\n"
            "Prove that the data access occurs without proper authorization by "
            "comparing responses for authorized vs unauthorized users.\n"
        ),
        SignalCategory.INPUT: (
            "## INPUT Exploit Rules\n"
            "### craft_payload\n"
            "Create a minimal payload that demonstrates the input handling vulnerability. "
            "For XSS, use alert(document.domain). For deserialization, use a safe RCE demo.\n\n"
            "### bypass_sanitizers\n"
            "If sanitizers exist, attempt to bypass them with encoding tricks, alternate "
            "syntax, or edge cases in the sanitization logic.\n"
        ),
        SignalCategory.CRYPTO: (
            "## CRYPTO Exploit Rules\n"
            "### demonstrate_weakness\n"
            "Show practical exploitation of the cryptographic weakness. For weak hashing, "
            "demonstrate collision or preimage. For weak encryption, show decryption.\n\n"
            "### recover_secrets\n"
            "If keys or secrets are exposed, demonstrate recovery and subsequent "
            "unauthorized access using the recovered material.\n"
        ),
        SignalCategory.FINANCIAL: (
            "## FINANCIAL Exploit Rules\n"
            "### demonstrate_financial_impact\n"
            "Show the financial manipulation in action: duplicate transactions, negative "
            "amounts, or price overrides. Use safe test values.\n\n"
            "### prove_consistency_violation\n"
            "Demonstrate that the exploit leaves the financial state inconsistent, "
            "such as credit without corresponding debit.\n"
        ),
        SignalCategory.PRIVILEGE: (
            "## PRIVILEGE Exploit Rules\n"
            "### escalate_privileges\n"
            "Demonstrate privilege escalation from a low-privilege account to higher "
            "privileges. Show the before and after state.\n\n"
            "### access_admin_functions\n"
            "Show that admin-only functionality is accessible after escalation. "
            "Include evidence of the elevated access.\n"
        ),
        SignalCategory.MEMORY: (
            "## MEMORY Exploit Rules\n"
            "### trigger_corruption\n"
            "Craft input that triggers the memory corruption. Demonstrate with ASAN "
            "or similar sanitizer output showing the violation.\n\n"
            "### demonstrate_control\n"
            "Show control over corrupted memory contents. For buffer overflow, show "
            "overwriting of adjacent data. Use sanitizer traces as evidence.\n"
        ),
        SignalCategory.INJECTION: (
            "## INJECTION Exploit Rules\n"
            "### craft_injection_payload\n"
            "Create an injection payload that demonstrates the vulnerability. For SQL "
            "injection, extract data. For command injection, execute a safe command.\n\n"
            "### escalate_injection\n"
            "Show the maximum impact achievable through the injection. Progress from "
            "data extraction to potential code execution if possible.\n"
        ),
        SignalCategory.CONCURRENCY: (
            "## CONCURRENCY Exploit Rules\n"
            "### trigger_race_condition\n"
            "Write concurrent requests or threads that reliably trigger the race "
            "condition. Show the inconsistent state produced.\n\n"
            "### demonstrate_impact\n"
            "Show the security impact of winning the race: duplicated transactions, "
            "privilege escalation, or bypass of security checks.\n"
        ),
    }

    layer_defaults = {
        "detection": default_detection,
        "triage": default_triage,
        "exploit": default_exploit,
    }

    defaults = layer_defaults.get(layer, default_detection)
    parts = []
    for category in categories:
        cat = category if isinstance(category, SignalCategory) else SignalCategory(category)
        if cat in defaults:
            parts.append(defaults[cat])

    if not parts:
        tier_desc = tier.value
        return (
            f"Analyze this code for potential vulnerabilities. "
            f"Sensitivity level: {tier_desc}. "
            f"Look for common security issues including input validation, "
            f"authentication, authorization, injection, and data exposure flaws."
        )

    return "\n".join(parts)
