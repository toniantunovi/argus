"""Function extraction from tree-sitter ASTs.

Walks tree-sitter parse trees to extract function and method definitions
for each supported language. Produces `Function` model instances with
name, source, parameters, decorators, visibility, and line ranges.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import tree_sitter

from argus.models.core import Function
from argus.recon.parser import parse_file

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_functions(
    file_path: Path, language: str | None = None
) -> list[Function]:
    """Extract all function definitions from a source file."""
    result = parse_file(file_path, language)
    if result is None:
        return []
    tree, lang = result
    source_bytes = file_path.read_bytes()

    extractors: dict[str, _Extractor] = {
        "python": _extract_python,
        "javascript": _extract_js_ts,
        "typescript": _extract_js_ts,
        "tsx": _extract_js_ts,
        "java": _extract_java,
        "go": _extract_go,
        "rust": _extract_rust,
        "c": _extract_c_cpp,
        "cpp": _extract_c_cpp,
        "ruby": _extract_ruby,
        "php": _extract_php,
    }

    extractor = extractors.get(lang)
    if extractor is None:
        return []

    return extractor(tree, source_bytes, file_path, lang)


# Type alias for extractor callables
_Extractor = Any  # Callable[[tree_sitter.Tree, bytes, Path, str], list[Function]]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _node_text(node: tree_sitter.Node) -> str:
    """Get the UTF-8 text of a tree-sitter node."""
    return node.text.decode("utf-8", errors="replace")


def _node_source(node: tree_sitter.Node, source_bytes: bytes) -> str:
    """Get the source text for a node from the original bytes."""
    return source_bytes[node.start_byte : node.end_byte].decode(
        "utf-8", errors="replace"
    )


def _walk_find(
    node: tree_sitter.Node, target_types: set[str]
) -> list[tree_sitter.Node]:
    """Recursively find all descendant nodes matching any of the target types."""
    results: list[tree_sitter.Node] = []
    _walk_find_impl(node, target_types, results)
    return results


def _walk_find_impl(
    node: tree_sitter.Node,
    target_types: set[str],
    results: list[tree_sitter.Node],
) -> None:
    if node.type in target_types:
        results.append(node)
    for child in node.children:
        _walk_find_impl(child, target_types, results)


def _make_function(
    node: tree_sitter.Node,
    source_bytes: bytes,
    file_path: Path,
    language: str,
    name: str,
    parameters: list[str] | None = None,
    return_type: str | None = None,
    decorators: list[str] | None = None,
    is_public: bool = True,
    start_line_override: int | None = None,
) -> Function:
    """Construct a Function model from a tree-sitter node."""
    # tree-sitter lines are 0-indexed; our model uses 1-indexed lines
    start_line = (start_line_override if start_line_override is not None
                  else node.start_point[0] + 1)
    end_line = node.end_point[0] + 1
    source = _node_source(node, source_bytes)

    return Function(
        name=name,
        file_path=file_path,
        start_line=start_line,
        end_line=end_line,
        source=source,
        language=language,
        parameters=parameters or [],
        return_type=return_type,
        decorators=decorators or [],
        is_public=is_public,
    )


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

def _extract_python(
    tree: tree_sitter.Tree,
    source_bytes: bytes,
    file_path: Path,
    language: str,
) -> list[Function]:
    """Extract Python function/method definitions.

    Handles:
    - function_definition
    - decorated_definition (extracts decorators, delegates to inner def)
    - Private = name starts with _
    """
    functions: list[Function] = []

    # Find all function definitions (including nested inside classes)
    func_nodes = _walk_find(
        tree.root_node, {"function_definition", "decorated_definition"}
    )

    # Avoid processing a function_definition that is the child of a
    # decorated_definition we already found. Build a set of such children.
    decorated_inner: set[int] = set()
    for node in func_nodes:
        if node.type == "decorated_definition":
            # The actual function def is the last named child
            for child in node.children:
                if child.type == "function_definition":
                    decorated_inner.add(child.id)

    for node in func_nodes:
        if node.id in decorated_inner:
            continue

        decorators: list[str] = []
        func_node: tree_sitter.Node

        if node.type == "decorated_definition":
            # Extract decorators
            for child in node.children:
                if child.type == "decorator":
                    decorators.append(_node_text(child).strip())
                elif child.type == "function_definition":
                    func_node = child
                    break
            else:
                continue  # no function_definition child found
        else:
            func_node = node

        name_node = func_node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _node_text(name_node)

        # Parameters
        params_node = func_node.child_by_field_name("parameters")
        parameters = _extract_python_params(params_node)

        # Return type annotation
        return_type_node = func_node.child_by_field_name("return_type")
        return_type = _node_text(return_type_node).lstrip("->").strip() if return_type_node else None

        # Visibility: private if starts with _
        is_public = not name.startswith("_")

        functions.append(
            _make_function(
                node,  # use the outer node (decorated_definition or function_definition)
                source_bytes,
                file_path,
                language,
                name=name,
                parameters=parameters,
                return_type=return_type,
                decorators=decorators,
                is_public=is_public,
            )
        )

    return functions


def _extract_python_params(params_node: tree_sitter.Node | None) -> list[str]:
    """Extract parameter names from a Python parameters node."""
    if params_node is None:
        return []
    params: list[str] = []
    for child in params_node.named_children:
        if child.type == "identifier":
            params.append(_node_text(child))
        elif child.type in (
            "typed_parameter",
            "default_parameter",
            "typed_default_parameter",
        ):
            name_child = child.child_by_field_name("name")
            if name_child is not None:
                params.append(_node_text(name_child))
            elif child.named_children:
                # Fallback: first named child is usually the name
                params.append(_node_text(child.named_children[0]))
        elif child.type in ("list_splat_pattern", "dictionary_splat_pattern"):
            # *args, **kwargs
            if child.named_children:
                params.append(_node_text(child))
    return params


# ---------------------------------------------------------------------------
# JavaScript / TypeScript / TSX
# ---------------------------------------------------------------------------

def _extract_js_ts(
    tree: tree_sitter.Tree,
    source_bytes: bytes,
    file_path: Path,
    language: str,
) -> list[Function]:
    """Extract JS/TS function declarations, methods, and arrow functions.

    Handles:
    - function_declaration / function
    - method_definition
    - arrow_function (when assigned via variable_declarator or lexical_declaration)
    - generator_function_declaration
    - export_statement wrapping any of the above
    """
    functions: list[Function] = []

    # -- Named function declarations --
    for node in _walk_find(
        tree.root_node,
        {"function_declaration", "generator_function_declaration"},
    ):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _node_text(name_node)
        params = _extract_js_params(node.child_by_field_name("parameters"))
        return_type = _extract_ts_return_type(node)
        is_public = _js_is_exported(node)

        functions.append(
            _make_function(
                node, source_bytes, file_path, language,
                name=name, parameters=params, return_type=return_type,
                is_public=is_public,
            )
        )

    # -- Method definitions (inside class bodies) --
    for node in _walk_find(tree.root_node, {"method_definition"}):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _node_text(name_node)
        params = _extract_js_params(node.child_by_field_name("parameters"))
        return_type = _extract_ts_return_type(node)
        # Methods are public unless prefixed with # (private fields) or name starts with _
        is_public = not name.startswith("_") and not name.startswith("#")

        decorators = _extract_js_decorators(node)

        functions.append(
            _make_function(
                node, source_bytes, file_path, language,
                name=name, parameters=params, return_type=return_type,
                is_public=is_public, decorators=decorators,
            )
        )

    # -- Arrow functions assigned to variables --
    for node in _walk_find(tree.root_node, {"lexical_declaration", "variable_declaration"}):
        for decl in node.named_children:
            if decl.type != "variable_declarator":
                continue
            value_node = decl.child_by_field_name("value")
            if value_node is None or value_node.type not in ("arrow_function", "function"):
                continue
            name_node = decl.child_by_field_name("name")
            if name_node is None:
                continue
            name = _node_text(name_node)
            params = _extract_js_params(value_node.child_by_field_name("parameters"))
            return_type = _extract_ts_return_type(value_node)
            is_public = _js_is_exported(node)

            functions.append(
                _make_function(
                    node, source_bytes, file_path, language,
                    name=name, parameters=params, return_type=return_type,
                    is_public=is_public,
                )
            )

    return functions


def _extract_js_params(params_node: tree_sitter.Node | None) -> list[str]:
    """Extract parameter names from JS/TS formal_parameters node."""
    if params_node is None:
        return []
    params: list[str] = []
    for child in params_node.named_children:
        if child.type == "identifier":
            params.append(_node_text(child))
        elif child.type in (
            "required_parameter",
            "optional_parameter",
            "rest_parameter",
        ):
            # TS typed params: first named child is usually the pattern/identifier
            pattern = child.child_by_field_name("pattern")
            if pattern is not None:
                params.append(_node_text(pattern))
            elif child.named_children:
                params.append(_node_text(child.named_children[0]))
        elif child.type == "assignment_pattern":
            left = child.child_by_field_name("left")
            if left is not None:
                params.append(_node_text(left))
        elif child.type in (
            "object_pattern",
            "array_pattern",
            "rest_pattern",
        ):
            params.append(_node_text(child))
    return params


def _extract_ts_return_type(node: tree_sitter.Node) -> str | None:
    """Extract TypeScript return type annotation if present."""
    ret = node.child_by_field_name("return_type")
    if ret is not None:
        text = _node_text(ret).strip()
        # Remove leading colon from type annotations
        if text.startswith(":"):
            text = text[1:].strip()
        return text
    return None


def _js_is_exported(node: tree_sitter.Node) -> bool:
    """Check if a node is exported (its parent is an export_statement)."""
    parent = node.parent
    if parent is not None and parent.type in (
        "export_statement",
        "export_default_declaration",
    ):
        return True
    return False


def _extract_js_decorators(node: tree_sitter.Node) -> list[str]:
    """Extract decorators preceding a method definition."""
    decorators: list[str] = []
    # In tree-sitter, decorators for class methods may appear as previous siblings
    sibling = node.prev_named_sibling
    while sibling is not None and sibling.type == "decorator":
        decorators.insert(0, _node_text(sibling).strip())
        sibling = sibling.prev_named_sibling
    return decorators


# ---------------------------------------------------------------------------
# Java
# ---------------------------------------------------------------------------

def _extract_java(
    tree: tree_sitter.Tree,
    source_bytes: bytes,
    file_path: Path,
    language: str,
) -> list[Function]:
    """Extract Java method and constructor declarations.

    Handles:
    - method_declaration
    - constructor_declaration
    - Modifiers: public/private/protected, annotations
    """
    functions: list[Function] = []

    for node in _walk_find(
        tree.root_node, {"method_declaration", "constructor_declaration"}
    ):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _node_text(name_node)

        # Parameters
        params_node = node.child_by_field_name("parameters")
        parameters = _extract_java_params(params_node)

        # Return type
        return_type = None
        type_node = node.child_by_field_name("type")
        if type_node is not None:
            return_type = _node_text(type_node)

        # Modifiers (public/private/protected) and annotations
        is_public = True  # default in Java (package-private ~ public for our purposes)
        decorators: list[str] = []
        modifiers_node = node.child_by_field_name("modifiers") or _find_child_type(
            node, "modifiers"
        )
        if modifiers_node is not None:
            mod_text = _node_text(modifiers_node).lower()
            if "private" in mod_text:
                is_public = False
            elif "protected" in mod_text:
                is_public = True  # treat protected as public for analysis
            # Extract annotations
            for child in modifiers_node.named_children:
                if child.type in ("annotation", "marker_annotation"):
                    decorators.append(_node_text(child).strip())

        functions.append(
            _make_function(
                node, source_bytes, file_path, language,
                name=name, parameters=parameters, return_type=return_type,
                decorators=decorators, is_public=is_public,
            )
        )

    return functions


def _extract_java_params(
    params_node: tree_sitter.Node | None,
) -> list[str]:
    """Extract parameter names from Java formal_parameters."""
    if params_node is None:
        return []
    params: list[str] = []
    for child in params_node.named_children:
        if child.type == "formal_parameter" or child.type == "spread_parameter":
            name_child = child.child_by_field_name("name")
            if name_child is not None:
                params.append(_node_text(name_child))
        elif child.type == "receiver_parameter":
            continue  # 'this' parameter in Java, skip
    return params


# ---------------------------------------------------------------------------
# Go
# ---------------------------------------------------------------------------

def _extract_go(
    tree: tree_sitter.Tree,
    source_bytes: bytes,
    file_path: Path,
    language: str,
) -> list[Function]:
    """Extract Go function and method declarations.

    Handles:
    - function_declaration
    - method_declaration (has receiver)
    - Public = name starts with uppercase letter
    """
    functions: list[Function] = []

    for node in _walk_find(
        tree.root_node, {"function_declaration", "method_declaration"}
    ):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _node_text(name_node)

        # Parameters
        params_node = node.child_by_field_name("parameters")
        parameters = _extract_go_params(params_node)

        # Return type
        return_type = None
        result_node = node.child_by_field_name("result")
        if result_node is not None:
            return_type = _node_text(result_node).strip()

        # Go visibility: exported = starts with uppercase
        is_public = name[0].isupper() if name else True

        functions.append(
            _make_function(
                node, source_bytes, file_path, language,
                name=name, parameters=parameters, return_type=return_type,
                is_public=is_public,
            )
        )

    return functions


def _extract_go_params(params_node: tree_sitter.Node | None) -> list[str]:
    """Extract parameter names from Go parameter_list."""
    if params_node is None:
        return []
    params: list[str] = []
    for child in params_node.named_children:
        if child.type == "parameter_declaration":
            # A parameter_declaration can have multiple names before the type
            name_child = child.child_by_field_name("name")
            if name_child is not None:
                params.append(_node_text(name_child))
            else:
                # Multiple names: iterate children for identifiers
                for sub in child.children:
                    if sub.type == "identifier":
                        params.append(_node_text(sub))
        elif child.type == "variadic_parameter_declaration":
            name_child = child.child_by_field_name("name")
            if name_child is not None:
                params.append(_node_text(name_child))
    return params


# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------

def _extract_rust(
    tree: tree_sitter.Tree,
    source_bytes: bytes,
    file_path: Path,
    language: str,
) -> list[Function]:
    """Extract Rust function items.

    Handles:
    - function_item
    - Public = has `pub` visibility modifier
    - Attributes (#[...]) are extracted as decorators
    """
    functions: list[Function] = []

    for node in _walk_find(tree.root_node, {"function_item"}):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _node_text(name_node)

        # Parameters
        params_node = node.child_by_field_name("parameters")
        parameters = _extract_rust_params(params_node)

        # Return type
        return_type = None
        ret_node = node.child_by_field_name("return_type")
        if ret_node is not None:
            return_type = _node_text(ret_node).lstrip("->").strip()

        # Visibility: check for pub keyword
        is_public = False
        vis_node = node.child_by_field_name("visibility_modifier")
        if vis_node is not None:
            is_public = True
        else:
            # Also check first children for visibility_modifier node type
            for child in node.children:
                if child.type == "visibility_modifier":
                    is_public = True
                    break

        # Attributes as decorators
        decorators = _extract_rust_attributes(node)

        functions.append(
            _make_function(
                node, source_bytes, file_path, language,
                name=name, parameters=parameters, return_type=return_type,
                decorators=decorators, is_public=is_public,
            )
        )

    return functions


def _extract_rust_params(
    params_node: tree_sitter.Node | None,
) -> list[str]:
    """Extract parameter names from Rust parameters node."""
    if params_node is None:
        return []
    params: list[str] = []
    for child in params_node.named_children:
        if child.type == "parameter":
            pattern = child.child_by_field_name("pattern")
            if pattern is not None:
                params.append(_node_text(pattern))
        elif child.type == "self_parameter":
            params.append(_node_text(child))
    return params


def _extract_rust_attributes(node: tree_sitter.Node) -> list[str]:
    """Extract #[...] attributes preceding a function_item."""
    decorators: list[str] = []
    # Attributes are typically previous siblings or within an attribute_item
    sibling = node.prev_named_sibling
    while sibling is not None and sibling.type == "attribute_item":
        decorators.insert(0, _node_text(sibling).strip())
        sibling = sibling.prev_named_sibling
    # Also check children of parent for attribute nodes
    # In some grammars attributes are direct children of the function node
    for child in node.children:
        if child.type == "attribute_item":
            decorators.append(_node_text(child).strip())
    return decorators


# ---------------------------------------------------------------------------
# C / C++
# ---------------------------------------------------------------------------

def _extract_c_cpp(
    tree: tree_sitter.Tree,
    source_bytes: bytes,
    file_path: Path,
    language: str,
) -> list[Function]:
    """Extract C/C++ function definitions.

    Handles:
    - function_definition
    - Static functions are marked as non-public
    """
    functions: list[Function] = []

    for node in _walk_find(tree.root_node, {"function_definition"}):
        # The declarator field contains the function name and parameters
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue

        # The declarator is typically a function_declarator
        func_decl = declarator
        if func_decl.type != "function_declarator":
            # Might be wrapped in a pointer_declarator
            func_decl = _find_child_type(declarator, "function_declarator")
            if func_decl is None:
                func_decl = declarator

        # Get name from the declarator field of the function_declarator
        name_node = func_decl.child_by_field_name("declarator")
        if name_node is None:
            # Try direct name
            name_node = func_decl.child_by_field_name("name")
        if name_node is None:
            # Fallback: first identifier child
            for child in func_decl.children:
                if child.type == "identifier" or child.type == "field_identifier":
                    name_node = child
                    break
        if name_node is None:
            continue

        # Unwrap qualified identifiers or scoped names (C++)
        if name_node.type in ("qualified_identifier", "scoped_identifier"):
            # Get the rightmost name part
            right = name_node.child_by_field_name("name")
            if right is not None:
                name_node = right

        name = _node_text(name_node)

        # Parameters
        params_node = func_decl.child_by_field_name("parameters")
        parameters = _extract_c_params(params_node)

        # Return type
        type_node = node.child_by_field_name("type")
        return_type = _node_text(type_node).strip() if type_node else None

        # Visibility: static = not public
        is_public = True
        # Check for storage class specifiers
        for child in node.children:
            if child.type == "storage_class_specifier" and _node_text(child) == "static":
                is_public = False
                break
        # Also check type specifiers
        if type_node is not None:
            type_text = _node_text(type_node)
            if "static" in type_text.split():
                is_public = False

        functions.append(
            _make_function(
                node, source_bytes, file_path, language,
                name=name, parameters=parameters, return_type=return_type,
                is_public=is_public,
            )
        )

    return functions


def _extract_c_params(params_node: tree_sitter.Node | None) -> list[str]:
    """Extract parameter names from C/C++ parameter_list."""
    if params_node is None:
        return []
    params: list[str] = []
    for child in params_node.named_children:
        if child.type == "parameter_declaration":
            decl = child.child_by_field_name("declarator")
            if decl is not None:
                # May be a pointer_declarator wrapping an identifier
                ident = _find_deepest_identifier(decl)
                if ident is not None:
                    params.append(_node_text(ident))
        elif child.type == "variadic_parameter":
            params.append("...")
    return params


def _find_deepest_identifier(node: tree_sitter.Node) -> tree_sitter.Node | None:
    """Find the deepest identifier in a declarator chain (for C/C++ pointer_declarator etc)."""
    if node.type in ("identifier", "field_identifier"):
        return node
    for child in node.children:
        result = _find_deepest_identifier(child)
        if result is not None:
            return result
    return None


# ---------------------------------------------------------------------------
# Ruby
# ---------------------------------------------------------------------------

def _extract_ruby(
    tree: tree_sitter.Tree,
    source_bytes: bytes,
    file_path: Path,
    language: str,
) -> list[Function]:
    """Extract Ruby method definitions.

    Handles:
    - method (instance methods)
    - singleton_method (class methods / self.method)
    - Private = name convention not strong in Ruby, but methods after
      `private` keyword are private. We use a simple heuristic.
    """
    functions: list[Function] = []

    for node in _walk_find(tree.root_node, {"method", "singleton_method"}):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _node_text(name_node)

        # Parameters
        params_node = node.child_by_field_name("parameters")
        parameters = _extract_ruby_params(params_node)

        # Ruby doesn't have explicit visibility in syntax on methods.
        # We treat all methods as public unless the name starts with _
        is_public = not name.startswith("_")

        functions.append(
            _make_function(
                node, source_bytes, file_path, language,
                name=name, parameters=parameters, is_public=is_public,
            )
        )

    return functions


def _extract_ruby_params(params_node: tree_sitter.Node | None) -> list[str]:
    """Extract parameter names from Ruby method_parameters."""
    if params_node is None:
        return []
    params: list[str] = []
    for child in params_node.named_children:
        if child.type == "identifier":
            params.append(_node_text(child))
        elif child.type in (
            "optional_parameter",
            "keyword_parameter",
            "splat_parameter",
            "hash_splat_parameter",
            "block_parameter",
        ):
            name_child = child.child_by_field_name("name")
            if name_child is not None:
                params.append(_node_text(name_child))
            elif child.named_children:
                params.append(_node_text(child.named_children[0]))
        elif child.type == "destructured_parameter":
            params.append(_node_text(child))
    return params


# ---------------------------------------------------------------------------
# PHP
# ---------------------------------------------------------------------------

def _extract_php(
    tree: tree_sitter.Tree,
    source_bytes: bytes,
    file_path: Path,
    language: str,
) -> list[Function]:
    """Extract PHP function and method declarations.

    Handles:
    - function_definition (standalone functions)
    - method_declaration (class methods)
    - Modifiers: public/private/protected
    """
    functions: list[Function] = []

    for node in _walk_find(
        tree.root_node, {"function_definition", "method_declaration"}
    ):
        name_node = node.child_by_field_name("name")
        if name_node is None:
            continue
        name = _node_text(name_node)

        # Parameters
        params_node = node.child_by_field_name("parameters")
        parameters = _extract_php_params(params_node)

        # Return type
        return_type = None
        ret_node = node.child_by_field_name("return_type")
        if ret_node is not None:
            return_type = _node_text(ret_node).lstrip(":").strip()

        # Visibility
        is_public = True
        if node.type == "method_declaration":
            # Check for visibility modifier in modifiers or direct children
            for child in node.children:
                if child.type == "visibility_modifier":
                    text = _node_text(child).lower()
                    if text in ("private", "protected"):
                        is_public = False
                    break

        functions.append(
            _make_function(
                node, source_bytes, file_path, language,
                name=name, parameters=parameters, return_type=return_type,
                is_public=is_public,
            )
        )

    return functions


def _extract_php_params(params_node: tree_sitter.Node | None) -> list[str]:
    """Extract parameter names from PHP formal_parameters."""
    if params_node is None:
        return []
    params: list[str] = []
    for child in params_node.named_children:
        if child.type == "simple_parameter":
            name_child = child.child_by_field_name("name")
            if name_child is not None:
                params.append(_node_text(name_child))
        elif child.type == "variadic_parameter":
            name_child = child.child_by_field_name("name")
            if name_child is not None:
                params.append(_node_text(name_child))
        elif child.type == "property_promotion_parameter":
            name_child = child.child_by_field_name("name")
            if name_child is not None:
                params.append(_node_text(name_child))
    return params


# ---------------------------------------------------------------------------
# Shared utility
# ---------------------------------------------------------------------------

def _find_child_type(
    node: tree_sitter.Node, type_name: str
) -> tree_sitter.Node | None:
    """Find the first direct child with the given type."""
    for child in node.children:
        if child.type == type_name:
            return child
    return None
