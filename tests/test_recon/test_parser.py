"""Tests for tree-sitter parsing module."""
from pathlib import Path

import pytest

from prowl.recon.parser import detect_language, parse_file, parse_source


class TestDetectLanguage:
    def test_python(self):
        assert detect_language(Path("app.py")) == "python"

    def test_javascript(self):
        assert detect_language(Path("server.js")) == "javascript"

    def test_jsx(self):
        assert detect_language(Path("component.jsx")) == "javascript"

    def test_typescript(self):
        assert detect_language(Path("app.ts")) == "typescript"

    def test_tsx(self):
        assert detect_language(Path("App.tsx")) == "tsx"

    def test_c(self):
        assert detect_language(Path("vuln.c")) == "c"

    def test_c_header(self):
        assert detect_language(Path("header.h")) == "c"

    def test_cpp(self):
        assert detect_language(Path("main.cpp")) == "cpp"

    def test_java(self):
        assert detect_language(Path("Main.java")) == "java"

    def test_go(self):
        assert detect_language(Path("main.go")) == "go"

    def test_rust(self):
        assert detect_language(Path("lib.rs")) == "rust"

    def test_ruby(self):
        assert detect_language(Path("app.rb")) == "ruby"

    def test_php(self):
        assert detect_language(Path("index.php")) == "php"

    def test_unsupported_returns_none(self):
        assert detect_language(Path("data.csv")) is None

    def test_case_insensitive(self):
        assert detect_language(Path("FILE.PY")) == "python"

    def test_no_extension(self):
        assert detect_language(Path("Makefile")) is None


class TestParseFile:
    def test_parse_python_file(self, python_app):
        result = parse_file(python_app / "app.py")
        assert result is not None
        tree, language = result
        assert language == "python"
        assert tree.root_node is not None
        assert tree.root_node.type == "module"

    def test_parse_c_file(self, c_project):
        result = parse_file(c_project / "vuln.c")
        assert result is not None
        tree, language = result
        assert language == "c"
        assert tree.root_node is not None
        assert tree.root_node.type == "translation_unit"

    def test_parse_js_file(self, node_app):
        result = parse_file(node_app / "server.js")
        assert result is not None
        tree, language = result
        assert language == "javascript"
        assert tree.root_node is not None
        assert tree.root_node.type == "program"

    def test_parse_unsupported_returns_none(self, tmp_path):
        txt_file = tmp_path / "data.txt"
        txt_file.write_text("hello world")
        assert parse_file(txt_file) is None

    def test_parse_nonexistent_returns_none(self):
        assert parse_file(Path("/nonexistent/file.py")) is None

    def test_parse_with_explicit_language(self, python_app):
        result = parse_file(python_app / "app.py", language="python")
        assert result is not None
        _, lang = result
        assert lang == "python"


class TestParseSource:
    def test_parse_python_source(self):
        source = b"def hello():\n    pass\n"
        tree = parse_source(source, "python")
        assert tree is not None
        assert tree.root_node.type == "module"

    def test_parse_c_source(self):
        source = b"int main() { return 0; }\n"
        tree = parse_source(source, "c")
        assert tree is not None
        assert tree.root_node.type == "translation_unit"

    def test_parse_js_source(self):
        source = b"function hello() { return 42; }\n"
        tree = parse_source(source, "javascript")
        assert tree is not None
        assert tree.root_node.type == "program"

    def test_parse_unsupported_language(self):
        assert parse_source(b"hello", "brainfuck") is None
