"""Tests for risk signal detection."""
from pathlib import Path

import pytest

from argus.models.core import Function, SignalCategory
from argus.recon.signals import detect_signals


FIXTURES_DIR = Path(__file__).parent.parent / "fixtures"


def _make_func(name, source, language="python", **kwargs):
    return Function(
        name=name,
        file_path=Path("/fake/file.py"),
        start_line=1,
        end_line=source.count("\n") + 1,
        source=source,
        language=language,
        **kwargs,
    )


class TestSQLInjectionSignals:
    def test_get_user_has_data_access_signals(self, python_app):
        from argus.recon.extractor import extract_functions

        funcs = extract_functions(python_app / "app.py")
        get_user = next(f for f in funcs if f.name == "get_user")
        signals = detect_signals(get_user)
        categories = {s.category for s in signals}
        assert SignalCategory.DATA_ACCESS in categories

    def test_raw_sql_select_detected(self):
        func = _make_func(
            "query_user",
            'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
        )
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "raw_sql_select" in signal_names or "py_cursor_execute" in signal_names

    def test_fstring_sql_injection_detected(self):
        func = _make_func(
            "bad_query",
            'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        )
        signals = detect_signals(func)
        categories = {s.category for s in signals}
        assert SignalCategory.DATA_ACCESS in categories or SignalCategory.INJECTION in categories


class TestCommandInjectionSignals:
    def test_run_command_has_injection_signals(self, python_app):
        from argus.recon.extractor import extract_functions

        funcs = extract_functions(python_app / "app.py")
        run_cmd = next(f for f in funcs if f.name == "run_command")
        signals = detect_signals(run_cmd)
        categories = {s.category for s in signals}
        assert SignalCategory.INJECTION in categories

    def test_os_system_detected(self):
        func = _make_func("cmd", "os.system(cmd)")
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "py_os_system" in signal_names

    def test_subprocess_call_detected(self):
        func = _make_func("run", "subprocess.call(cmd, shell=True)")
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "py_subprocess" in signal_names or "py_shell_true" in signal_names


class TestMemorySignals:
    def test_parse_header_has_memory_signals(self, c_project):
        from argus.recon.extractor import extract_functions

        funcs = extract_functions(c_project / "vuln.c")
        parse_header = next(f for f in funcs if f.name == "parse_header")
        signals = detect_signals(parse_header)
        categories = {s.category for s in signals}
        assert SignalCategory.MEMORY in categories

    def test_memcpy_detected(self):
        func = _make_func("copy", "memcpy(dst, src, len);", language="c")
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "memcpy_call" in signal_names

    def test_malloc_detected(self):
        func = _make_func("alloc", "char *p = malloc(128);", language="c")
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "malloc_call" in signal_names

    def test_strcpy_detected(self):
        func = _make_func("copy", "strcpy(buf, data);", language="c")
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "strcpy_call" in signal_names

    def test_free_detected(self):
        func = _make_func("cleanup", "free(buf);", language="c")
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "free_call" in signal_names


class TestCryptoSignals:
    def test_validate_token_has_crypto_signals(self, python_app):
        from argus.recon.extractor import extract_functions

        funcs = extract_functions(python_app / "app.py")
        vt = next(f for f in funcs if f.name == "validate_token")
        signals = detect_signals(vt)
        categories = {s.category for s in signals}
        assert SignalCategory.CRYPTO in categories

    def test_md5_detected(self):
        func = _make_func(
            "hash_it",
            "import hashlib\nhashlib.md5(data.encode()).hexdigest()",
        )
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "py_hashlib" in signal_names or "md5_usage" in signal_names

    def test_js_crypto_detected(self):
        func = _make_func(
            "hash",
            "crypto.createHash('md5').update(s).digest('hex')",
            language="javascript",
        )
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "js_crypto" in signal_names or "md5_usage" in signal_names


class TestAuthSignals:
    def test_flask_route_decorator(self):
        func = _make_func(
            "handler",
            '@app.route("/api")\ndef handler(): pass',
        )
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "flask_route" in signal_names

    def test_login_required_decorator(self):
        func = _make_func(
            "protected",
            "@login_required\ndef protected(): pass",
        )
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "py_login_required" in signal_names

    def test_express_route(self):
        func = _make_func(
            "get_handler",
            "app.get('/api', (req, res) => {})",
            language="javascript",
        )
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "express_route" in signal_names


class TestNoSignals:
    def test_safe_copy_minimal_signals(self, c_project):
        from argus.recon.extractor import extract_functions

        funcs = extract_functions(c_project / "safe.c")
        safe_copy = next(f for f in funcs if f.name == "safe_copy")
        signals = detect_signals(safe_copy)
        # safe_copy uses memcpy (memory) and printf, but should NOT have
        # injection, auth, crypto, financial, privilege, or concurrency signals
        non_memory_categories = {
            s.category for s in signals
        } - {SignalCategory.MEMORY}
        # It should have at most memory signals and possibly input-related
        # No injection, auth, crypto, financial, privilege
        dangerous = non_memory_categories & {
            SignalCategory.INJECTION,
            SignalCategory.AUTH,
            SignalCategory.CRYPTO,
            SignalCategory.FINANCIAL,
            SignalCategory.PRIVILEGE,
        }
        assert len(dangerous) == 0


class TestLanguageFiltering:
    def test_python_pattern_not_matched_for_c(self):
        func = _make_func(
            "main",
            'os.system("ls")',
            language="c",
        )
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "py_os_system" not in signal_names

    def test_c_memory_pattern_not_matched_for_python(self):
        func = _make_func(
            "alloc",
            "p = malloc(128)",
            language="python",
        )
        signals = detect_signals(func)
        signal_names = {s.name for s in signals}
        assert "malloc_call" not in signal_names


class TestSignalLineNumbers:
    def test_signal_has_line_number(self):
        func = _make_func(
            "test",
            "line1\nos.system(cmd)\nline3",
            parameters=["cmd"],
        )
        func.start_line = 10
        signals = detect_signals(func)
        injection_signals = [s for s in signals if s.category == SignalCategory.INJECTION]
        if injection_signals:
            assert injection_signals[0].line_number >= 10
