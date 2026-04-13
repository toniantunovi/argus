"""Risk signal detection across 9 vulnerability categories.

Scans function source code against language-aware regex patterns to detect
risk signals such as authentication operations, data access, input parsing,
crypto usage, financial operations, privilege changes, memory ops, injection
vectors, and concurrency primitives.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from argus.models.core import Function, RiskSignal, SignalCategory

# ---------------------------------------------------------------------------
# Pattern definition
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class SignalPattern:
    """A named regex pattern for detecting a risk signal."""
    name: str
    regex: re.Pattern[str]
    # Optional language constraint; ``None`` means all languages.
    languages: frozenset[str] | None = None


# Convenience builder
def _p(
    name: str,
    pattern: str,
    *,
    flags: int = re.IGNORECASE,
    languages: frozenset[str] | None = None,
) -> SignalPattern:
    return SignalPattern(
        name=name,
        regex=re.compile(pattern, flags),
        languages=languages,
    )


_PY = frozenset({"python"})
_JS_TS = frozenset({"javascript", "typescript", "tsx"})
_C_CPP = frozenset({"c", "cpp"})
_JAVA = frozenset({"java"})
_GO = frozenset({"go"})
_RUST = frozenset({"rust"})
_RUBY = frozenset({"ruby"})
_PHP = frozenset({"php"})


# ---------------------------------------------------------------------------
# Category weights
# ---------------------------------------------------------------------------

CATEGORY_WEIGHTS: dict[SignalCategory, float] = {
    SignalCategory.AUTH: 1.5,
    SignalCategory.DATA_ACCESS: 1.0,
    SignalCategory.INPUT: 1.0,
    SignalCategory.CRYPTO: 1.2,
    SignalCategory.FINANCIAL: 1.3,
    SignalCategory.PRIVILEGE: 1.4,
    SignalCategory.MEMORY: 1.5,
    SignalCategory.INJECTION: 1.5,
    SignalCategory.CONCURRENCY: 1.0,
}


# ---------------------------------------------------------------------------
# Pattern tables per category
# ---------------------------------------------------------------------------

AUTH_PATTERNS: list[SignalPattern] = [
    # General (all languages)
    _p("login_call", r"\blogin\s*\("),
    _p("logout_call", r"\blogout\s*\("),
    _p("authenticate_call", r"\bauthenticat[ei]\w*\s*\("),
    _p("check_permission", r"\bcheck_perm(ission)?\w*\s*\("),
    _p("authorize_call", r"\bauthoriz[ei]\w*\s*\("),
    _p("jwt_verify", r"\bjwt\s*\.\s*verify\b"),
    _p("jwt_decode", r"\bjwt\s*\.\s*decode\b"),
    _p("jwt_sign", r"\bjwt\s*\.\s*sign\b"),
    _p("token_create", r"\b(create|generate|issue)_?token\s*\("),
    _p("token_validate", r"\b(validate|verify)_?token\s*\("),
    _p("token_refresh", r"\brefresh_?token\b"),
    _p("session_create", r"\bsession\s*\.\s*(create|set|start)\b"),
    _p("session_destroy", r"\bsession\s*\.\s*(destroy|delete|clear|invalidate)\b"),
    _p("oauth_call", r"\boauth\w*\s*\("),
    _p("password_check", r"\b(check|verify|validate)_?password\s*\("),
    _p("password_hash", r"\bhash_?password\s*\("),
    _p("bcrypt_call", r"\bbcrypt\s*\.\s*(hash|compare|check)\b"),
    _p("api_key_check", r"\bapi[_\s]?key\b"),

    # Python decorators
    _p("py_login_required", r"@login_required\b", languages=_PY),
    _p("py_auth_decorator", r"@(auth|requires_auth|authenticated)\b", languages=_PY),
    _p("py_permission_required", r"@permission_required\b", languages=_PY),
    _p("py_requires_role", r"@(requires_role|role_required)\b", languages=_PY),

    # Java/Spring annotations
    _p("java_secured", r"@Secured\b", languages=_JAVA, flags=0),
    _p("java_preauthorize", r"@PreAuthorize\b", languages=_JAVA, flags=0),
    _p("java_rolesallowed", r"@RolesAllowed\b", languages=_JAVA, flags=0),

    # JS/TS middleware
    _p("js_passport", r"\bpassport\s*\.\s*(authenticate|use)\b", languages=_JS_TS),
    _p("js_auth_middleware", r"\b(authMiddleware|requireAuth|isAuthenticated)\b", languages=_JS_TS),

    # Go
    _p("go_auth_handler", r"\b(AuthHandler|AuthMiddleware|RequireAuth)\b", languages=_GO, flags=0),

    # Route decorators
    _p("flask_route", r"@app\.\s*route\b", languages=_PY),
    _p("django_url_pattern", r"\bpath\s*\(\s*['\"]", languages=_PY),
    _p("express_route", r"\b(app|router)\.\s*(get|post|put|delete|patch)\s*\(", languages=_JS_TS),
]

DATA_ACCESS_PATTERNS: list[SignalPattern] = [
    # SQL
    _p("raw_sql_select", r"\bSELECT\s+.+\s+FROM\b"),
    _p("raw_sql_insert", r"\bINSERT\s+INTO\b"),
    _p("raw_sql_update", r"\bUPDATE\s+\w+\s+SET\b"),
    _p("raw_sql_delete", r"\bDELETE\s+FROM\b"),

    # Python ORMs / DB
    _p("py_cursor_execute", r"\bcursor\s*\.\s*execute\w*\s*\(", languages=_PY),
    _p("py_django_orm", r"\bModel\s*\.\s*objects\b", languages=_PY),
    _p("py_django_queryset", r"\.\s*(filter|exclude|get|all|values|annotate|aggregate)\s*\(", languages=_PY),
    _p("py_sqlalchemy_query", r"\bsession\s*\.\s*(query|execute|add|delete|merge)\b", languages=_PY),
    _p("py_sqlalchemy_text", r"\btext\s*\(\s*['\"]", languages=_PY),

    # JS/TS ORMs / DB
    _p("js_sequelize", r"\b\w+\.\s*(findAll|findOne|findByPk|create|update|destroy)\s*\(", languages=_JS_TS),
    _p("js_mongoose", r"\b\w+\.\s*(find|findById|findOne|save|remove|deleteOne|deleteMany)\s*\(", languages=_JS_TS),
    _p("js_knex", r"\bknex\s*\(", languages=_JS_TS),
    _p("js_prisma", r"\bprisma\s*\.\s*\w+\s*\.\s*(find|create|update|delete|upsert)\w*\s*\(", languages=_JS_TS),

    # Java JDBC / JPA
    _p("java_jdbc", r"\b(Statement|PreparedStatement|ResultSet)\b", languages=_JAVA),
    _p("java_jpa_repo", r"\b(JpaRepository|CrudRepository)\b", languages=_JAVA),
    _p("java_entitymanager", r"\bentityManager\s*\.\s*(find|persist|merge|remove|createQuery)\b", languages=_JAVA),

    # Go DB
    _p("go_db_query", r"\bdb\s*\.\s*(Query|QueryRow|Exec|Prepare)\b", languages=_GO, flags=0),
    _p("go_sql_open", r"\bsql\s*\.\s*Open\b", languages=_GO, flags=0),

    # General
    _p("generic_query", r"\.\s*query\s*\("),
    _p("generic_find", r"\.\s*find\s*\("),
    _p("generic_execute", r"\.\s*execute\s*\("),
]

INPUT_PATTERNS: list[SignalPattern] = [
    # Python
    _p("py_request_json", r"\brequest\s*\.\s*json\b", languages=_PY),
    _p("py_request_form", r"\brequest\s*\.\s*(form|data|files)\b", languages=_PY),
    _p("py_request_args", r"\brequest\s*\.\s*(args|params|GET|POST|query_params)\b", languages=_PY),
    _p("py_request_body", r"\brequest\s*\.\s*body\b", languages=_PY),
    _p("py_json_loads", r"\bjson\s*\.\s*loads?\s*\(", languages=_PY),
    _p("py_pickle_load", r"\bpickle\s*\.\s*(load|loads)\b", languages=_PY),
    _p("py_yaml_load", r"\byaml\s*\.\s*(load|safe_load|unsafe_load)\b", languages=_PY),
    _p("py_xml_parse", r"\b(ET|ElementTree|etree|xml)\s*\.\s*(parse|fromstring)\b", languages=_PY),

    # JS/TS
    _p("js_json_parse", r"\bJSON\s*\.\s*parse\s*\(", languages=_JS_TS),
    _p("js_req_body", r"\breq\s*\.\s*body\b", languages=_JS_TS),
    _p("js_req_params", r"\breq\s*\.\s*(params|query)\b", languages=_JS_TS),
    _p("js_req_headers", r"\breq\s*\.\s*headers\b", languages=_JS_TS),

    # Java
    _p("java_getparam", r"\b(getParameter|getHeader|getInputStream|getReader)\s*\(", languages=_JAVA),
    _p("java_requestbody", r"@RequestBody\b", languages=_JAVA, flags=0),
    _p("java_pathvariable", r"@PathVariable\b", languages=_JAVA, flags=0),
    _p("java_requestparam", r"@RequestParam\b", languages=_JAVA, flags=0),
    _p("java_objectmapper", r"\bObjectMapper\b", languages=_JAVA, flags=0),

    # Go
    _p("go_read_body", r"\br\.Body\b", languages=_GO, flags=0),
    _p("go_form_value", r"\br\s*\.\s*FormValue\b", languages=_GO, flags=0),
    _p("go_json_decoder", r"\bjson\s*\.\s*NewDecoder\b", languages=_GO, flags=0),
    _p("go_json_unmarshal", r"\bjson\s*\.\s*Unmarshal\b", languages=_GO, flags=0),

    # General
    _p("deserialize", r"\bdeserializ[ei]\w*\s*\("),
    _p("unmarshal", r"\bunmarshal\w*\s*\("),
    _p("generic_parse_input", r"\bparse\s*\("),

    # PHP
    _p("php_get_post", r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b", languages=_PHP, flags=0),
    _p("php_input", r"\bfile_get_contents\s*\(\s*['\"]php://input", languages=_PHP),
]

CRYPTO_PATTERNS: list[SignalPattern] = [
    # Python
    _p("py_hashlib", r"\bhashlib\s*\.\s*(md5|sha1|sha256|sha512|sha224|sha384|new)\b", languages=_PY),
    _p("py_hmac", r"\bhmac\s*\.\s*(new|compare_digest|HMAC)\b", languages=_PY),
    _p("py_cryptography", r"\bfrom\s+cryptography\b", languages=_PY),
    _p("py_pycrypto", r"\bfrom\s+(Crypto|Cryptodome)\b", languages=_PY, flags=0),
    _p("py_secrets", r"\bsecrets\s*\.\s*(token|choice|randbelow)\b", languages=_PY),
    _p("py_random_security", r"\brandom\s*\.\s*(choice|randint|randrange|sample)\b", languages=_PY),

    # JS/TS
    _p("js_crypto", r"\bcrypto\s*\.\s*(createHash|createHmac|createSign|createCipher|randomBytes)\b", languages=_JS_TS),
    _p("js_webcrypto", r"\bsubtle\s*\.\s*(encrypt|decrypt|sign|verify|digest|generateKey)\b", languages=_JS_TS),

    # Java
    _p("java_messagedigest", r"\bMessageDigest\s*\.\s*getInstance\b", languages=_JAVA, flags=0),
    _p("java_cipher", r"\bCipher\s*\.\s*getInstance\b", languages=_JAVA, flags=0),
    _p("java_keygenerator", r"\bKeyGenerator\b", languages=_JAVA, flags=0),
    _p("java_securerandom", r"\bSecureRandom\b", languages=_JAVA, flags=0),
    _p("java_mac", r"\bMac\s*\.\s*getInstance\b", languages=_JAVA, flags=0),

    # Go
    _p("go_crypto", r"\bcrypto/(sha256|sha1|md5|hmac|aes|rsa|ecdsa|ed25519)\b", languages=_GO),

    # General
    _p("md5_usage", r"\bmd5\b"),
    _p("sha1_usage", r"\bsha1\b"),
    _p("sha256_usage", r"\bsha256\b"),
    _p("aes_usage", r"\baes\b"),
    _p("rsa_usage", r"\brsa\b"),
    _p("encrypt_call", r"\bencrypt\w*\s*\("),
    _p("decrypt_call", r"\bdecrypt\w*\s*\("),
    _p("sign_call", r"\b(sign|verify_signature)\s*\("),

    # Rust
    _p("rust_crypto_import", r"\buse\s+(sha2|hmac|aes|rsa|ring|openssl)\b", languages=_RUST),
]

FINANCIAL_PATTERNS: list[SignalPattern] = [
    _p("charge_call", r"\bcharge\s*\("),
    _p("transfer_call", r"\btransfer\s*\("),
    _p("refund_call", r"\brefund\s*\("),
    _p("payment_call", r"\b(process_?payment|create_?payment|submit_?payment)\s*\("),
    _p("balance_access", r"\bbalance\b"),
    _p("amount_access", r"\b(amount|total|price|cost)\b"),
    _p("stripe_api", r"\bstripe\s*\.\s*(charges?|paymentIntents?|refunds?|customers?)\b"),
    _p("paypal_api", r"\bpaypal\b"),
    _p("payment_gateway", r"\b(payment_?gateway|billing|invoice)\b"),
    _p("credit_debit", r"\b(credit|debit)\s*\("),
    _p("withdraw", r"\bwithdraw\w*\s*\("),
    _p("deposit", r"\bdeposit\w*\s*\("),
    _p("currency_op", r"\b(convert_?currency|exchange_?rate)\b"),

    # Python-specific
    _p("py_decimal_money", r"\bDecimal\s*\(", languages=_PY),
]

PRIVILEGE_PATTERNS: list[SignalPattern] = [
    # Unix/POSIX
    _p("setuid_call", r"\bsetuid\s*\("),
    _p("setgid_call", r"\bsetgid\s*\("),
    _p("seteuid_call", r"\bseteuid\s*\("),
    _p("setegid_call", r"\bsetegid\s*\("),
    _p("setresuid_call", r"\bsetresuid\s*\("),
    _p("chroot_call", r"\bchroot\s*\("),
    _p("drop_privileges", r"\bdrop_privil\w*\s*\("),
    _p("capability_set", r"\bcap_(set|get|clear)\w*\s*\("),
    _p("prctl_call", r"\bprctl\s*\("),

    # General
    _p("sudo_exec", r"\bsudo\b"),
    _p("root_check", r"\b(is_root|is_admin|is_superuser)\b"),
    _p("role_escalation", r"\b(escalat|elevat)\w*(priv|role|perm)\w*"),
    _p("chmod_call", r"\bchmod\s*\("),
    _p("chown_call", r"\bchown\s*\("),

    # Python
    _p("py_os_setuid", r"\bos\s*\.\s*(setuid|setgid|seteuid|setegid)\s*\(", languages=_PY),

    # Go
    _p("go_syscall_setuid", r"\bsyscall\s*\.\s*(Setuid|Setgid|Seteuid|Setegid)\b", languages=_GO, flags=0),

    # Java
    _p("java_access_controller", r"\bAccessController\b", languages=_JAVA, flags=0),
    _p("java_security_manager", r"\bSecurityManager\b", languages=_JAVA, flags=0),
]

MEMORY_PATTERNS: list[SignalPattern] = [
    # C/C++
    _p("malloc_call", r"\bmalloc\s*\(", languages=_C_CPP),
    _p("calloc_call", r"\bcalloc\s*\(", languages=_C_CPP),
    _p("realloc_call", r"\brealloc\s*\(", languages=_C_CPP),
    _p("free_call", r"\bfree\s*\(", languages=_C_CPP),
    _p("memcpy_call", r"\bmemcpy\s*\(", languages=_C_CPP),
    _p("memmove_call", r"\bmemmove\s*\(", languages=_C_CPP),
    _p("memset_call", r"\bmemset\s*\(", languages=_C_CPP),
    _p("strcpy_call", r"\bstrcpy\s*\(", languages=_C_CPP),
    _p("strncpy_call", r"\bstrncpy\s*\(", languages=_C_CPP),
    _p("strcat_call", r"\bstrcat\s*\(", languages=_C_CPP),
    _p("sprintf_call", r"\bsprintf\s*\(", languages=_C_CPP),
    _p("gets_call", r"\bgets\s*\(", languages=_C_CPP),
    _p("scanf_call", r"\bscanf\s*\(", languages=_C_CPP),
    _p("buffer_index", r"\[\s*\w+\s*[\+\-]\s*\w+\s*\]", languages=_C_CPP),
    _p("pointer_arithmetic", r"\*\s*\(\s*\w+\s*[\+\-]", languages=_C_CPP),
    _p("new_delete", r"\b(new|delete)\s", languages=_C_CPP),
    _p("alloca_call", r"\balloca\s*\(", languages=_C_CPP),

    # Rust unsafe
    _p("rust_unsafe_block", r"\bunsafe\s*\{", languages=_RUST),
    _p("rust_raw_pointer", r"\*\s*(const|mut)\b", languages=_RUST),
    _p("rust_transmute", r"\btransmute\b", languages=_RUST),
    _p("rust_from_raw", r"\bfrom_raw\b", languages=_RUST),

    # Go
    _p("go_unsafe_pointer", r"\bunsafe\s*\.\s*Pointer\b", languages=_GO, flags=0),
    _p("go_cgo", r"\bC\s*\.\s*(malloc|free|CString|GoBytes)\b", languages=_GO, flags=0),

    # General
    _p("buffer_alloc", r"\b(Buffer|ArrayBuffer|SharedArrayBuffer)\s*\.\s*(alloc|from)\b"),
]

INJECTION_PATTERNS: list[SignalPattern] = [
    # Python
    _p("py_eval", r"\beval\s*\(", languages=_PY),
    _p("py_exec", r"\bexec\s*\(", languages=_PY),
    _p("py_compile", r"\bcompile\s*\(", languages=_PY),
    _p("py_os_system", r"\bos\s*\.\s*system\s*\(", languages=_PY),
    _p("py_os_popen", r"\bos\s*\.\s*popen\s*\(", languages=_PY),
    _p("py_subprocess", r"\bsubprocess\s*\.\s*(call|run|Popen|check_output|check_call)\s*\(", languages=_PY),
    _p("py_shell_true", r"\bshell\s*=\s*True\b", languages=_PY),
    _p("py_format_sql", r"""(f['"]|\.format\s*\().*\b(SELECT|INSERT|UPDATE|DELETE)\b""", languages=_PY),
    _p("py_template_render", r"\b(render_template_string|Markup)\s*\(", languages=_PY),
    _p("py_importlib", r"\b__import__\s*\(", languages=_PY),

    # JS/TS
    _p("js_eval", r"\beval\s*\(", languages=_JS_TS),
    _p("js_function_constructor", r"\bnew\s+Function\s*\(", languages=_JS_TS),
    _p("js_child_process", r"\b(exec|execSync|spawn|execFile)\s*\(", languages=_JS_TS),
    _p("js_settimeout_string", r"\bsetTimeout\s*\(\s*['\"]", languages=_JS_TS),
    _p("js_innerhtml", r"\binnerHTML\s*=", languages=_JS_TS),
    _p("js_document_write", r"\bdocument\s*\.\s*write\s*\(", languages=_JS_TS),
    _p("js_sql_concat", r"""['"`]\s*\+\s*\w+.*\b(SELECT|INSERT|UPDATE|DELETE)\b""", languages=_JS_TS),

    # Java
    _p("java_runtime_exec", r"\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\b", languages=_JAVA),
    _p("java_processbuilder", r"\bProcessBuilder\b", languages=_JAVA, flags=0),
    _p("java_scriptengine", r"\bScriptEngine\s*\.\s*eval\b", languages=_JAVA, flags=0),
    _p("java_sql_concat", r""""\s*\+\s*\w+.*\b(SELECT|INSERT|UPDATE|DELETE)\b""", languages=_JAVA),

    # C/C++
    _p("c_system", r"\bsystem\s*\(", languages=_C_CPP),
    _p("c_popen", r"\bpopen\s*\(", languages=_C_CPP),
    _p("c_execvp", r"\bexecv[pe]?\s*\(", languages=_C_CPP),
    _p("c_execl", r"\bexecl[pe]?\s*\(", languages=_C_CPP),
    _p("c_dlopen", r"\bdlopen\s*\(", languages=_C_CPP),

    # Go
    _p("go_exec_command", r"\bexec\s*\.\s*Command\b", languages=_GO, flags=0),
    _p("go_os_exec", r"\bos\s*\.\s*Exec\b", languages=_GO, flags=0),

    # Rust
    _p("rust_command", r"\bCommand\s*::\s*new\b", languages=_RUST),

    # PHP
    _p("php_exec", r"\b(exec|system|passthru|shell_exec|popen|proc_open)\s*\(", languages=_PHP),
    _p("php_eval", r"\beval\s*\(", languages=_PHP),
    _p("php_preg_e", r"\bpreg_replace\s*\(.*/e\b", languages=_PHP),

    # Ruby
    _p("ruby_system", r"\b(system|exec|spawn)\s*\(", languages=_RUBY),
    _p("ruby_backtick", r"`[^`]*`", languages=_RUBY),

    # General
    _p("template_injection", r"\b(render|template)\w*\s*\(.*\b(user|input|param|request)\b"),
    _p("sql_string_concat", r"""['"]\s*\+\s*\w+.*(?:SELECT|INSERT|UPDATE|DELETE)\b"""),
]

CONCURRENCY_PATTERNS: list[SignalPattern] = [
    # Python
    _p("py_threading", r"\bthreading\s*\.\s*(Thread|Lock|RLock|Semaphore|Event|Condition|Barrier)\b", languages=_PY),
    _p("py_multiprocessing", r"\bmultiprocessing\s*\.\s*(Process|Pool|Queue|Pipe)\b", languages=_PY),
    _p("py_asyncio", r"\basyncio\s*\.\s*(gather|create_task|ensure_future|wait)\b", languages=_PY),
    _p("py_concurrent", r"\bconcurrent\s*\.\s*futures\b", languages=_PY),
    _p("py_global_state", r"\bglobal\s+\w+", languages=_PY),

    # JS/TS
    _p("js_worker", r"\b(Worker|SharedWorker|ServiceWorker)\b", languages=_JS_TS),
    _p("js_shared_buffer", r"\bSharedArrayBuffer\b", languages=_JS_TS),
    _p("js_atomics", r"\bAtomics\s*\.\s*(add|sub|store|load|wait|notify|exchange|compareExchange)\b", languages=_JS_TS),

    # Java
    _p("java_synchronized", r"\bsynchronized\b", languages=_JAVA),
    _p("java_thread", r"\b(Thread|Runnable|Callable|ExecutorService|FutureTask)\b", languages=_JAVA, flags=0),
    _p("java_concurrent", r"\bjava\.util\.concurrent\b", languages=_JAVA),
    _p("java_atomic", r"\b(AtomicInteger|AtomicLong|AtomicReference|AtomicBoolean)\b", languages=_JAVA, flags=0),
    _p("java_lock", r"\b(ReentrantLock|ReadWriteLock|Semaphore|CountDownLatch)\b", languages=_JAVA, flags=0),
    _p("java_volatile", r"\bvolatile\b", languages=_JAVA),

    # Go
    _p("go_goroutine", r"\bgo\s+\w+\s*\(", languages=_GO),
    _p("go_mutex", r"\bsync\s*\.\s*(Mutex|RWMutex|WaitGroup|Once|Pool|Map)\b", languages=_GO, flags=0),
    _p("go_channel", r"\b(chan\s+\w+|<-\s*\w+|\w+\s*<-)", languages=_GO),
    _p("go_atomic", r"\batomic\s*\.\s*(Add|Load|Store|CompareAndSwap|Swap)\w*\b", languages=_GO, flags=0),

    # C/C++
    _p("c_pthread", r"\bpthread_(create|mutex|rwlock|cond|barrier)\w*\s*\(", languages=_C_CPP),
    _p("c_mutex", r"\bmtx_(lock|unlock|init|destroy)\s*\(", languages=_C_CPP),
    _p("c_atomic", r"\batomic_\w+\s*\(", languages=_C_CPP),
    _p("cpp_thread", r"\bstd\s*::\s*(thread|mutex|lock_guard|unique_lock|shared_lock|condition_variable)\b", languages=_C_CPP),
    _p("c_volatile", r"\bvolatile\b", languages=_C_CPP),

    # Rust
    _p("rust_mutex", r"\b(Mutex|RwLock|Arc)\s*::\s*new\b", languages=_RUST),
    _p("rust_atomic", r"\bAtomic\w+\s*::\s*new\b", languages=_RUST),
    _p("rust_thread_spawn", r"\bthread\s*::\s*spawn\b", languages=_RUST),
    _p("rust_channel", r"\b(mpsc|crossbeam)\s*::\s*(channel|unbounded|bounded)\b", languages=_RUST),
    _p("rust_send_sync", r"\b(Send|Sync)\b", languages=_RUST, flags=0),

    # General
    _p("generic_lock", r"\b(lock|unlock|acquire|release)\s*\("),
    _p("generic_mutex", r"\bmutex\b"),
    _p("race_condition_comment", r"\brace\s+condition\b"),
]


# ---------------------------------------------------------------------------
# Master table
# ---------------------------------------------------------------------------

SIGNAL_TABLE: dict[SignalCategory, list[SignalPattern]] = {
    SignalCategory.AUTH: AUTH_PATTERNS,
    SignalCategory.DATA_ACCESS: DATA_ACCESS_PATTERNS,
    SignalCategory.INPUT: INPUT_PATTERNS,
    SignalCategory.CRYPTO: CRYPTO_PATTERNS,
    SignalCategory.FINANCIAL: FINANCIAL_PATTERNS,
    SignalCategory.PRIVILEGE: PRIVILEGE_PATTERNS,
    SignalCategory.MEMORY: MEMORY_PATTERNS,
    SignalCategory.INJECTION: INJECTION_PATTERNS,
    SignalCategory.CONCURRENCY: CONCURRENCY_PATTERNS,
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def detect_signals(function: Function) -> list[RiskSignal]:
    """Scan a function's source against all pattern tables and return matched signals.

    Patterns are filtered by language when a pattern has a language constraint.
    """
    language = function.language
    source = function.source
    signals: list[RiskSignal] = []

    for category, patterns in SIGNAL_TABLE.items():
        weight = CATEGORY_WEIGHTS[category]
        for sp in patterns:
            # Skip patterns that don't apply to this language
            if sp.languages is not None and language not in sp.languages:
                continue

            match = sp.regex.search(source)
            if match is None:
                continue

            # Compute line number relative to the function start
            match_pos = match.start()
            line_offset = source[:match_pos].count("\n")
            line_number = function.start_line + line_offset

            signals.append(
                RiskSignal(
                    category=category,
                    name=sp.name,
                    description=f"Matched pattern '{sp.name}' in {category.value} category",
                    weight=weight,
                    line_number=line_number,
                    pattern=sp.regex.pattern,
                )
            )

    return signals
