"""Framework detection for implicit protections."""
from __future__ import annotations

import re

from argus.models.core import Function

FRAMEWORK_PATTERNS = {
    "django": [
        re.compile(r"from django\b"), re.compile(r"import django\b"),
        re.compile(r"@.*csrf_exempt"), re.compile(r"urlpatterns"),
    ],
    "flask": [
        re.compile(r"from flask\b"), re.compile(r"import flask\b"),
        re.compile(r"@app\.route"), re.compile(r"Flask\("),
    ],
    "fastapi": [
        re.compile(r"from fastapi\b"), re.compile(r"FastAPI\("),
        re.compile(r"@app\.(get|post|put|delete|patch)"),
    ],
    "express": [
        re.compile(r"require\(['\"]express['\"]\)"), re.compile(r"from ['\"]express['\"]"),
        re.compile(r"app\.(get|post|put|delete|patch|use)\("),
        re.compile(r"router\.(get|post|put|delete|patch|use)\("),
    ],
    "spring": [
        re.compile(r"@(RestController|Controller|RequestMapping|GetMapping|PostMapping)"),
        re.compile(r"import org\.springframework"),
    ],
    "rails": [
        re.compile(r"class \w+ < ApplicationController"),
        re.compile(r"before_action"), re.compile(r"skip_before_action"),
    ],
}

FRAMEWORK_PROTECTIONS = {
    "django": "Django provides: CSRF protection (middleware), SQL injection protection (ORM parameterization), XSS auto-escaping in templates, clickjacking protection (X-Frame-Options middleware).",
    "flask": "Flask provides: No automatic CSRF protection (requires Flask-WTF). No auto-escaping outside Jinja2 templates. No built-in ORM protections.",
    "fastapi": "FastAPI provides: Automatic request validation via Pydantic. No CSRF protection (API-first). SQL injection protection depends on ORM choice.",
    "express": "Express provides: No automatic protections. Helmet.js adds security headers. CSRF requires csurf middleware. SQL injection depends on query builder.",
    "spring": "Spring provides: CSRF protection (enabled by default), SQL injection protection (JPA/JDBC parameterization), XSS protection via output encoding.",
    "rails": "Rails provides: CSRF protection (enabled by default), SQL injection protection (ActiveRecord parameterization), XSS auto-escaping in views.",
}


def detect_framework(func: Function, all_functions: dict[str, Function] | None = None) -> str | None:
    """Detect which web framework is in use, return protection description."""
    # Check the function itself and its file
    sources_to_check = [func.source]
    if all_functions:
        same_file = [f.source for f in all_functions.values() if f.file_path == func.file_path and f.identifier != func.identifier]
        sources_to_check.extend(same_file[:5])  # check a few from same file

    combined = "\n".join(sources_to_check)
    for framework_name, patterns in FRAMEWORK_PATTERNS.items():
        for pattern in patterns:
            if pattern.search(combined):
                return FRAMEWORK_PROTECTIONS[framework_name]
    return None
