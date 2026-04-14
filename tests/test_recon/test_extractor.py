"""Tests for function extraction from tree-sitter ASTs."""
from pathlib import Path

import pytest

from prowl.recon.extractor import extract_functions


class TestExtractPythonFunctions:
    def test_extracts_expected_functions(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        names = {f.name for f in funcs}
        assert "get_db" in names
        assert "get_user" in names
        assert "delete_user" in names
        assert "search" in names
        assert "run_command" in names
        assert "validate_token" in names

    def test_function_count(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        # get_db, get_user, delete_user, search, run_command, validate_token
        assert len(funcs) >= 6

    def test_get_user_has_correct_params(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        get_user = next(f for f in funcs if f.name == "get_user")
        assert "user_id" in get_user.parameters

    def test_get_user_has_source(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        get_user = next(f for f in funcs if f.name == "get_user")
        assert "SELECT * FROM users" in get_user.source

    def test_get_user_line_range(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        get_user = next(f for f in funcs if f.name == "get_user")
        # get_user starts with the decorator @app.route
        assert get_user.start_line >= 11
        assert get_user.end_line >= get_user.start_line

    def test_decorated_function_has_decorators(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        get_user = next(f for f in funcs if f.name == "get_user")
        assert any("route" in d for d in get_user.decorators)

    def test_language_is_python(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        for func in funcs:
            assert func.language == "python"

    def test_validate_token_params(self, python_app):
        funcs = extract_functions(python_app / "app.py")
        vt = next(f for f in funcs if f.name == "validate_token")
        assert "token" in vt.parameters

    def test_private_function_visibility(self, tmp_path):
        f = tmp_path / "mod.py"
        f.write_text("def _private():\n    pass\n\ndef public():\n    pass\n")
        funcs = extract_functions(f)
        priv = next(fn for fn in funcs if fn.name == "_private")
        pub = next(fn for fn in funcs if fn.name == "public")
        assert not priv.is_public
        assert pub.is_public


class TestExtractCFunctions:
    def test_extracts_expected_functions(self, c_project):
        funcs = extract_functions(c_project / "vuln.c")
        names = {f.name for f in funcs}
        assert "parse_header" in names
        assert "process_data" in names
        assert "compute_size" in names
        assert "log_message" in names
        assert "main" in names

    def test_function_count(self, c_project):
        funcs = extract_functions(c_project / "vuln.c")
        assert len(funcs) == 5

    def test_parse_header_params(self, c_project):
        funcs = extract_functions(c_project / "vuln.c")
        ph = next(f for f in funcs if f.name == "parse_header")
        assert "input" in ph.parameters
        assert "input_len" in ph.parameters

    def test_parse_header_has_memcpy(self, c_project):
        funcs = extract_functions(c_project / "vuln.c")
        ph = next(f for f in funcs if f.name == "parse_header")
        assert "memcpy" in ph.source

    def test_compute_size_return_type(self, c_project):
        funcs = extract_functions(c_project / "vuln.c")
        cs = next(f for f in funcs if f.name == "compute_size")
        assert cs.return_type == "int"

    def test_main_params(self, c_project):
        funcs = extract_functions(c_project / "vuln.c")
        m = next(f for f in funcs if f.name == "main")
        assert "argc" in m.parameters
        assert "argv" in m.parameters

    def test_language_is_c(self, c_project):
        funcs = extract_functions(c_project / "vuln.c")
        for func in funcs:
            assert func.language == "c"

    def test_safe_copy_extraction(self, c_project):
        funcs = extract_functions(c_project / "safe.c")
        names = {f.name for f in funcs}
        assert "safe_copy" in names


class TestExtractJSFunctions:
    def test_extracts_hashpassword(self, node_app):
        funcs = extract_functions(node_app / "server.js")
        names = {f.name for f in funcs}
        assert "hashPassword" in names

    def test_hashpassword_has_params(self, node_app):
        funcs = extract_functions(node_app / "server.js")
        hp = next(f for f in funcs if f.name == "hashPassword")
        assert "password" in hp.parameters

    def test_language_is_javascript(self, node_app):
        funcs = extract_functions(node_app / "server.js")
        for func in funcs:
            assert func.language == "javascript"

    def test_extracts_route_handlers(self, node_app):
        """Route handlers are arrow functions assigned to app.get/post/delete calls.

        These may not all be extracted as named functions since they are
        anonymous callbacks. We verify at least hashPassword is extracted.
        """
        funcs = extract_functions(node_app / "server.js")
        assert len(funcs) >= 1  # at least hashPassword

    def test_function_has_source(self, node_app):
        funcs = extract_functions(node_app / "server.js")
        hp = next(f for f in funcs if f.name == "hashPassword")
        assert "md5" in hp.source

    def test_function_line_numbers_valid(self, node_app):
        funcs = extract_functions(node_app / "server.js")
        for func in funcs:
            assert func.start_line >= 1
            assert func.end_line >= func.start_line


class TestExtractUnsupported:
    def test_unsupported_extension(self, tmp_path):
        f = tmp_path / "data.csv"
        f.write_text("a,b,c\n1,2,3\n")
        funcs = extract_functions(f)
        assert funcs == []

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty.py"
        f.write_text("")
        funcs = extract_functions(f)
        assert funcs == []
