"""
slicer.py
Uses Tree-Sitter to extract the exact vulnerable function
from a C++ file given a file path and line number.
"""

from tree_sitter_languages import get_language, get_parser
from pathlib import Path


PARSER = get_parser("cpp")


def _find_function_node(node, target_line: int):
    """Walk AST to find the function definition containing target_line."""
    FUNCTION_TYPES = {
        "function_definition",
        "method_definition",
    }

    if node.type in FUNCTION_TYPES:
        # tree-sitter lines are 0-indexed
        start = node.start_point[0] + 1
        end = node.end_point[0] + 1
        if start <= target_line <= end:
            return node

    for child in node.children:
        result = _find_function_node(child, target_line)
        if result:
            return result

    return None


def _extract_function_name(node) -> str:
    """Pull the function name out of a function_definition node."""
    for child in node.children:
        if child.type == "function_declarator":
            for subchild in child.children:
                if subchild.type in ("identifier", "qualified_identifier", "destructor_name"):
                    return subchild.text.decode("utf-8")
        if child.type == "identifier":
            return child.text.decode("utf-8")
    return "unknown_function"


def slice_function(file_path: str, line_number: int) -> dict | None:
    """
    Given a file and a vulnerable line number, extract the full
    function containing that line.

    Returns dict with function_name, source_code, start_line,
    end_line, file — or None if not found.
    """
    path = Path(file_path)
    if not path.exists():
        print(f"[slicer] File not found: {file_path}")
        return None

    source_bytes = path.read_bytes()
    tree = PARSER.parse(source_bytes)

    func_node = _find_function_node(tree.root_node, line_number)
    if func_node is None:
        print(f"[slicer] No function found at line {line_number} in {path.name}")
        return None

    function_name = _extract_function_name(func_node)
    source_lines = source_bytes.decode("utf-8", errors="replace").splitlines()

    start = func_node.start_point[0]   # 0-indexed
    end = func_node.end_point[0]       # 0-indexed
    source_code = "\n".join(source_lines[start:end + 1])

    print(f"[slicer] Sliced '{function_name}' lines {start+1}–{end+1} from {path.name}")

    return {
        "function_name": function_name,
        "source_code": source_code,
        "start_line": start + 1,
        "end_line": end + 1,
        "file": file_path,
    }
