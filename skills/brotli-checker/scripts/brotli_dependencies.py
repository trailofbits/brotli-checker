"""Offline dependency-declaration leads; no installation or version verdicts."""

from __future__ import annotations

import ast
import json
import re
import tomllib
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

MAX_DEPENDENCY_MATCHES = 20
DEPENDENCY_MATCH_LOOKAHEAD = MAX_DEPENDENCY_MATCHES + 1
MAX_JSON_DEPENDENCY_NODES = 100_000

MANIFEST_NAMES = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "gradle.lockfile",
    "cargo.toml",
    "cargo.lock",
    "go.mod",
    "go.sum",
    "pyproject.toml",
    "requirements.txt",
    "uv.lock",
    "poetry.lock",
    "cmakelists.txt",
    "cmakecache.txt",
    "module.bazel",
    "module.bazel.lock",
    "workspace",
    "workspace.bazel",
    "deps",
    "dockerfile",
    "containerfile",
    ".gitmodules",
    "vcpkg.json",
    "conanfile.txt",
    "conanfile.py",
    "bom.json",
    "metadata",
    "pkg-info",
    "setup.py",
    "setup.cfg",
    "pipfile",
    "pipfile.lock",
    "gemfile",
    "gemfile.lock",
    "composer.json",
    "composer.lock",
    "packages.config",
    "packages.lock.json",
}

DEPENDENCY = re.compile(
    r"brotli(?:4j|dec|common|enc)?|woff2|workerd|(?<![\w-])undici(?![\w-])",
    re.IGNORECASE,
)

RUBY_GEM_CALL = re.compile(r"^\s*gem\s*(?:\(\s*)?['\"](?P<name>[^'\"]+)['\"]")

RUBY_GEMSPEC_DEPENDENCY = re.compile(
    r"^\s*(?:[A-Za-z_]\w*\s*\.\s*)?add_(?:runtime_)?dependency\s*"
    r"(?:\(\s*)?['\"](?P<name>[^'\"]+)['\"]"
)

RUBY_LOCK_PACKAGE = re.compile(r"^\s{2,}(?P<name>[A-Za-z0-9_.-]+)(?:\s+\([^\r\n]*\))?\s*!?\s*$")

DOTNET_XML_NON_CODE = re.compile(
    r"<!--(?:[\s\S]*?-->|[\s\S]*\Z)|<!\[CDATA\[(?:[\s\S]*?\]\]>|[\s\S]*\Z)"
)


def dependency_lines(text: str) -> Iterator[str]:
    for match in re.finditer(r"[^\r\n]*(?:\r\n|\r|\n|$)", text):
        if match.start() == len(text):
            return
        yield match.group().rstrip("\r\n")


def append_match(matches: list[dict], match: dict | None) -> bool:
    """Append one retained row and report that the lookahead population is full."""
    if match is not None and len(matches) < DEPENDENCY_MATCH_LOOKAHEAD:
        matches.append(match)
    return len(matches) >= DEPENDENCY_MATCH_LOOKAHEAD


def extend_matches(matches: list[dict], additions: list[dict]) -> bool:
    remaining = DEPENDENCY_MATCH_LOOKAHEAD - len(matches)
    if remaining > 0:
        matches.extend(additions[:remaining])
    return len(matches) >= DEPENDENCY_MATCH_LOOKAHEAD


def incomplete_match(kind: str, reason: str) -> dict:
    return {
        "text": f"Incomplete {kind} dependency parsing: {reason}; selection is unresolved.",
        "parse_incomplete": True,
    }


def rendered_value(value: object) -> str:
    try:
        return json.dumps(value, ensure_ascii=True)[:300]
    except RecursionError:
        return "<value nesting exceeds safe rendering depth>"


def ruby_lock_dependency_matches(text: str) -> list[dict]:
    matches = []
    section = ""
    for line_number, line in enumerate(dependency_lines(text), 1):
        if line and not line[0].isspace():
            section = line.strip()
        match = RUBY_LOCK_PACKAGE.fullmatch(line)
        if (
            section in {"GEM", "GIT", "PATH", "DEPENDENCIES"}
            and match is not None
            and DEPENDENCY.search(match["name"])
            and append_match(matches, {"line": line_number, "text": line[:300]})
        ):
            return matches
    return matches


def ruby_dependency_matches(text: str, name: str) -> list[dict]:
    if name == "gemfile.lock":
        return ruby_lock_dependency_matches(text)
    pattern = RUBY_GEM_CALL if name == "gemfile" else RUBY_GEMSPEC_DEPENDENCY
    matches = []
    block_comment = False
    for line_number, line in enumerate(dependency_lines(text), 1):
        if line.startswith("=begin"):
            block_comment = True
            continue
        if block_comment:
            if line.startswith("=end"):
                block_comment = False
            continue
        match = pattern.match(line)
        if (
            match is not None
            and DEPENDENCY.search(match["name"])
            and append_match(matches, {"line": line_number, "text": line[:300]})
        ):
            return matches
    return matches


def composer_mapping_matches(value: object, field: str) -> list[dict]:
    if not isinstance(value, dict):
        return []
    matches = []
    for dependency, constraint in value.items():
        if (
            isinstance(dependency, str)
            and DEPENDENCY.search(dependency)
            and append_match(
                matches,
                {
                    "field": f"{field}.{dependency}",
                    "text": rendered_value(constraint),
                },
            )
        ):
            return matches
    return matches


def composer_package_matches(package: dict, field: str) -> list[dict]:
    matches = []
    package_name = package.get("name")
    if (
        isinstance(package_name, str)
        and DEPENDENCY.search(package_name)
        and append_match(matches, {"field": f"{field}.name", "text": package_name[:300]})
    ):
        return matches
    for dependency_field in (
        "require",
        "require-dev",
        "provide",
        "replace",
        "suggest",
    ):
        if extend_matches(
            matches,
            composer_mapping_matches(package.get(dependency_field), f"{field}.{dependency_field}"),
        ):
            return matches
    return matches


def composer_lock_matches(metadata: dict) -> list[dict]:
    matches = []
    for field in ("platform", "platform-dev"):
        if extend_matches(matches, composer_mapping_matches(metadata.get(field), field)):
            return matches
    for group in ("packages", "packages-dev"):
        packages = metadata.get(group, [])
        if not isinstance(packages, list):
            continue
        for index, package in enumerate(packages):
            if isinstance(package, dict) and extend_matches(
                matches, composer_package_matches(package, f"{group}[{index}]")
            ):
                return matches
    return matches


def composer_dependency_matches(text: str, name: str) -> list[dict]:
    try:
        metadata = json.loads(text)
    except RecursionError:
        return [incomplete_match("Composer JSON", "nesting exceeds the parser depth")]
    except json.JSONDecodeError:
        return (
            [{"text": "Unparseable Composer metadata mentioning Brotli-related components."}]
            if DEPENDENCY.search(text)
            else []
        )
    if not isinstance(metadata, dict):
        return (
            [{"text": "Unexpected Composer metadata mentioning Brotli-related components."}]
            if DEPENDENCY.search(text)
            else []
        )
    matches = []
    for field in ("require", "require-dev", "provide", "replace", "suggest"):
        if extend_matches(matches, composer_mapping_matches(metadata.get(field), field)):
            return matches
    if name == "composer.lock":
        extend_matches(matches, composer_lock_matches(metadata))
    return matches


def dependency_matches(text: str, name: str) -> list[dict]:
    if name in {"gemfile", "gemfile.lock"} or name.endswith(".gemspec"):
        return ruby_dependency_matches(text, name)
    if name in {"composer.json", "composer.lock"}:
        return composer_dependency_matches(text, name)
    scoped = scoped_dependency_matches(text, name)
    if scoped is not None:
        return scoped
    if name == "pyproject.toml":
        return pyproject_dependency_matches(text)
    matches = []
    for line_number, line in enumerate(dependency_lines(text), 1):
        if DEPENDENCY.search(line) and append_match(
            matches, {"line": line_number, "text": line[:300]}
        ):
            return matches
    return matches


def nested_value(metadata: object, field: str) -> object:
    value = metadata
    for key in field.split("."):
        value = value.get(key, {}) if isinstance(value, dict) else {}
    return value


def dependency_string_matches(value: object, field: str) -> list[dict]:
    matches = []
    pending = [(value, field)]
    visited = 0
    while pending:
        current, current_field = pending.pop()
        visited += 1
        if visited > MAX_JSON_DEPENDENCY_NODES:
            append_match(
                matches,
                incomplete_match("Python project", "dependency nesting exceeds the node limit"),
            )
            return matches
        if isinstance(current, str):
            if DEPENDENCY.search(current) and append_match(
                matches, {"field": current_field, "text": current[:300]}
            ):
                return matches
        elif isinstance(current, list):
            pending.extend((item, current_field) for item in reversed(current))
        elif isinstance(current, dict):
            pending.extend((item, current_field) for item in reversed(tuple(current.values())))
    return matches


def dependency_mapping_key_matches(value: object, field: str) -> list[dict]:
    if not isinstance(value, dict):
        return []
    matches = []
    for package, constraint in value.items():
        if (
            isinstance(package, str)
            and DEPENDENCY.search(package)
            and append_match(
                matches,
                {"field": f"{field}.{package}", "text": rendered_value(constraint)},
            )
        ):
            return matches
    return matches


def pyproject_dependency_matches(  # noqa: C901 -- Distinct package-manager field ownership.
    text: str,
) -> list[dict]:
    try:
        metadata = tomllib.loads(text)
    except RecursionError:
        return [incomplete_match("Python project TOML", "nesting exceeds the parser depth")]
    except tomllib.TOMLDecodeError:
        # Preserve a lead when malformed metadata cannot be parsed.
        return (
            [{"text": "Unparseable Python metadata mentioning Brotli-related components."}]
            if DEPENDENCY.search(text)
            else []
        )
    string_sections = (
        "project.dependencies",
        "project.optional-dependencies",
        "dependency-groups",
        "build-system.requires",
        "tool.pdm.dev-dependencies",
    )
    matches = []
    for field in string_sections:
        if extend_matches(matches, dependency_string_matches(nested_value(metadata, field), field)):
            return matches
    for field in (
        "tool.poetry.dependencies",
        "tool.poetry.dev-dependencies",
        "tool.uv.sources",
    ):
        if extend_matches(
            matches, dependency_mapping_key_matches(nested_value(metadata, field), field)
        ):
            return matches
    poetry_groups = nested_value(metadata, "tool.poetry.group")
    if isinstance(poetry_groups, dict):
        for group, configuration in poetry_groups.items():
            dependencies = (
                configuration.get("dependencies", {}) if isinstance(configuration, dict) else {}
            )
            if extend_matches(
                matches,
                dependency_mapping_key_matches(
                    dependencies, f"tool.poetry.group.{group}.dependencies"
                ),
            ):
                return matches
    return matches


def dependency_manifest(name: str) -> bool:
    return (
        name in MANIFEST_NAMES
        or name.startswith(("dockerfile.", "containerfile."))
        or (name.startswith("requirements") and name.endswith((".txt", ".in")))
        or name.endswith(
            (
                ".cmake",
                ".spdx.json",
                ".cdx.json",
                ".bzl",
                ".gemspec",
                ".csproj",
                ".fsproj",
                ".vbproj",
                ".props",
                ".targets",
                ".nuspec",
                ".deps.json",
            )
        )
    )


PYTHON_SETUP_DEPENDENCY_FIELDS = {
    "install_requires",
    "extras_require",
    "setup_requires",
    "tests_require",
}

DOTNET_XML_DEPENDENCY_ITEM = re.compile(
    r"<(?P<tag>(?:[A-Za-z_][\w.-]*:)?(?:GlobalPackageReference|PackageDownload|"
    r"PackageReference|PackageVersion|dependency|package))\b(?P<attributes>[^<>]{0,8192})>",
    re.IGNORECASE,
)

DOTNET_XML_ATTRIBUTE = re.compile(
    r"(?P<name>Include|Update|id)\s*=\s*(?P<quote>['\"])(?P<value>[^'\"]*)(?P=quote)",
    re.IGNORECASE,
)


def dependency_field_match(field: str, value: str) -> dict | None:
    if not DEPENDENCY.search(value):
        return None
    return {"field": field, "text": value[:300]}


def python_setup_literal_strings(
    node: ast.AST, assignments: dict[str, ast.AST]
) -> Iterator[tuple[str, int | None]]:
    pending = [node]
    seen = set()
    while pending:
        current = pending.pop()
        if id(current) in seen:
            continue
        seen.add(id(current))
        if isinstance(current, ast.Constant) and isinstance(current.value, str):
            yield current.value, getattr(current, "lineno", None)
        elif isinstance(current, (ast.List, ast.Tuple, ast.Set)):
            pending.extend(reversed(current.elts))
        elif isinstance(current, ast.Dict):
            pending.extend(reversed(current.values))
        elif isinstance(current, ast.BinOp) and isinstance(current.op, ast.Add):
            pending.extend((current.right, current.left))
        elif isinstance(current, ast.Name) and current.id in assignments:
            pending.append(assignments[current.id])


def resolved_setup_node(node: ast.AST, assignments: dict[str, ast.AST]) -> ast.AST:
    seen = set()
    while isinstance(node, ast.Name) and node.id in assignments and node.id not in seen:
        seen.add(node.id)
        node = assignments[node.id]
    return node


def setup_dependency_keywords(
    call: ast.Call, assignments: dict[str, ast.AST]
) -> Iterator[tuple[str, ast.AST]]:
    for keyword in call.keywords:
        if keyword.arg in PYTHON_SETUP_DEPENDENCY_FIELDS:
            yield keyword.arg, keyword.value
        elif keyword.arg is None:
            mapping = resolved_setup_node(keyword.value, assignments)
            if not isinstance(mapping, ast.Dict):
                continue
            for key, value in zip(mapping.keys, mapping.values, strict=True):
                if (
                    isinstance(key, ast.Constant)
                    and isinstance(key.value, str)
                    and key.value in PYTHON_SETUP_DEPENDENCY_FIELDS
                ):
                    yield key.value, value


def python_setup_dependency_matches(  # noqa: C901 -- Static AST literals and keyword ownership.
    text: str,
) -> list[dict]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError):
        pattern = re.compile(
            r"\b(?:install_requires|extras_require|setup_requires|tests_require)\s*="
            r"[^\r\n]{0,300}brotli",
            re.IGNORECASE,
        )
        matches = []
        for line_number, line in enumerate(dependency_lines(text), 1):
            if pattern.search(line) and append_match(
                matches, {"line": line_number, "text": line[:300]}
            ):
                return matches
        return matches

    assignments: dict[str, ast.AST] = {
        target.id: statement.value
        for statement in tree.body
        if isinstance(statement, (ast.Assign, ast.AnnAssign)) and statement.value is not None
        for target in (
            statement.targets if isinstance(statement, ast.Assign) else (statement.target,)
        )
        if isinstance(target, ast.Name)
    }
    matches = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if not (
            (isinstance(node.func, ast.Name) and node.func.id == "setup")
            or (isinstance(node.func, ast.Attribute) and node.func.attr == "setup")
        ):
            continue
        for field, value_node in setup_dependency_keywords(node, assignments):
            for value, line in python_setup_literal_strings(value_node, assignments):
                match = dependency_field_match(field, value)
                if match is not None:
                    if line is not None:
                        match["line"] = line
                    if append_match(matches, match):
                        return matches
    return matches


def python_setup_cfg_dependency_matches(  # noqa: C901,PLR0912 -- INI continuation state machine.
    text: str,
) -> list[dict]:
    matches = []
    section = ""
    active_field: str | None = None
    for line_number, line in enumerate(dependency_lines(text), 1):
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            active_field = None
            continue
        if not stripped or stripped.startswith(("#", ";")):
            continue
        value = ""
        if line[:1].isspace() and active_field is not None:
            value = stripped
            key_value = None
        else:
            key_value = re.match(r"^\s*([^=:#]+?)\s*[=:]\s*(.*)$", line)
        if key_value is not None:
            key = key_value.group(1).strip().lower()
            value = key_value.group(2).strip()
            if section == "options" and key in PYTHON_SETUP_DEPENDENCY_FIELDS:
                active_field = key
            elif section == "options.extras_require":
                active_field = f"options.extras_require.{key}"
            else:
                active_field = None
        elif not (line[:1].isspace() and active_field is not None):
            active_field = None
        if active_field is not None:
            match = dependency_field_match(active_field, value)
            if match is not None:
                match["line"] = line_number
                if append_match(matches, match):
                    return matches
    return matches


def python_toml_dependency_matches(  # noqa: C901 -- Parse/fallback and bounded field extraction.
    text: str,
) -> list[dict]:
    try:
        metadata = tomllib.loads(text)
    except RecursionError:
        return [incomplete_match("Pipfile TOML", "nesting exceeds the parser depth")]
    except tomllib.TOMLDecodeError:
        pattern = re.compile(r"^\s*['\"]?([^'\"=]+)['\"]?\s*=", re.MULTILINE)
        matches = []
        for match in pattern.finditer(text):
            if DEPENDENCY.search(match.group(1)) and append_match(
                matches,
                {
                    "field": f"unparsed.{match.group(1).strip()}",
                    "text": match.group(0)[:300],
                },
            ):
                return matches
        return matches
    matches = []
    for section in ("packages", "dev-packages"):
        packages = metadata.get(section, {})
        if not isinstance(packages, dict):
            continue
        for package, constraint in packages.items():
            match = dependency_field_match(
                f"{section}.{package}", package if isinstance(package, str) else ""
            )
            if match is not None:
                match["text"] = rendered_value(constraint)
                if append_match(matches, match):
                    return matches
    return matches


def python_lock_dependency_matches(  # noqa: C901 -- Parse/fallback and bounded field extraction.
    text: str,
) -> list[dict]:
    try:
        metadata = json.loads(text)
    except RecursionError:
        return [incomplete_match("Pipfile lock JSON", "nesting exceeds the parser depth")]
    except json.JSONDecodeError:
        return (
            [{"text": "Unparseable Pipfile lock mentioning a Brotli dependency key."}]
            if re.search(r"['\"]brotli(?:cffi)?['\"]\s*:", text, re.IGNORECASE)
            else []
        )
    if not isinstance(metadata, dict):
        return []
    matches = []
    for section in ("default", "develop"):
        packages = metadata.get(section, {})
        if not isinstance(packages, dict):
            continue
        for package, constraint in packages.items():
            match = dependency_field_match(
                f"{section}.{package}", package if isinstance(package, str) else ""
            )
            if match is not None:
                match["text"] = rendered_value(constraint)
                if append_match(matches, match):
                    return matches
    return matches


def python_requirement_matches(  # noqa: C901 -- PEP 508, VCS, editable and path forms.
    text: str,
) -> list[dict]:
    matches = []
    for line_number, line in enumerate(dependency_lines(text), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith(("-e ", "--editable ")):
            stripped = stripped.split(maxsplit=1)[1]
        elif stripped.startswith("--editable="):
            stripped = stripped.partition("=")[2]
        elif stripped.startswith("-"):
            continue
        egg = re.search(r"[#&]egg=(?P<name>[A-Za-z0-9_.-]+)", stripped)
        if egg is not None:
            identity = egg.group("name")
        elif direct := re.match(
            r"(?P<name>[A-Za-z0-9_.-]+(?:\[[^\]]+\])?)\s*@\s*(?P<source>.+)", stripped
        ):
            identity = direct.group("name") + direct.group("source")
        elif stripped.startswith(
            ("git+", "http://", "https://", "file:", "./", "../", ".\\", "..\\", "/")
        ) or re.match(r"^[A-Za-z]:[\\/]", stripped):
            identity = stripped
        else:
            requirement = re.match(r"(?P<name>[A-Za-z0-9_.-]+)(?P<extras>\[[^\]]+\])?", stripped)
            identity = requirement.group(0) if requirement is not None else ""
            if "/" in stripped or "\\" in stripped:
                identity += stripped
        if DEPENDENCY.search(identity) and append_match(
            matches, {"line": line_number, "text": line[:300]}
        ):
            return matches
    return matches


def dotnet_xml_dependency_matches(text: str, name: str) -> list[dict]:
    matches = []
    code = DOTNET_XML_NON_CODE.sub(lambda match: re.sub(r"[^\r\n]", " ", match.group()), text)
    for index, item in enumerate(DOTNET_XML_DEPENDENCY_ITEM.finditer(code)):
        tag = item.group("tag").rsplit(":", 1)[-1]
        attribute = DOTNET_XML_ATTRIBUTE.search(item.group("attributes"))
        if attribute is None:
            continue
        value = attribute.group("value")
        match = dependency_field_match(
            f"{name}.{tag}[{index}].{attribute.group('name').lower()}", value
        )
        if append_match(matches, match):
            return matches
    return matches


def json_dependency_keys(value: object, field: str) -> list[dict]:
    matches = []
    pending = [(value, field)]
    visited = 0
    while pending:
        current, current_field = pending.pop()
        if not isinstance(current, dict):
            continue
        for package, metadata in current.items():
            visited += 1
            if visited > MAX_JSON_DEPENDENCY_NODES:
                append_match(
                    matches,
                    incomplete_match(".NET JSON", "dependency keys exceed the node limit"),
                )
                return matches
            if not isinstance(package, str):
                continue
            if append_match(matches, dependency_field_match(f"{current_field}.{package}", package)):
                return matches
            if isinstance(metadata, dict):
                pending.append((metadata.get("dependencies"), f"{current_field}.{package}"))
    return matches


def dotnet_json_dependency_matches(text: str, name: str) -> list[dict]:
    try:
        metadata = json.loads(text)
    except RecursionError:
        return [incomplete_match(".NET JSON", "nesting exceeds the parser depth")]
    except json.JSONDecodeError:
        return (
            [{"text": "Unparseable .NET metadata mentioning a Brotli dependency key."}]
            if re.search(r"['\"][^'\"]*brotli[^'\"]*['\"]\s*:", text, re.IGNORECASE)
            else []
        )
    if not isinstance(metadata, dict):
        return []
    field = "dependencies" if name == "packages.lock.json" else "targets"
    groups = metadata.get(field, {})
    matches = json_dependency_keys(
        groups if name == "packages.lock.json" else metadata.get("libraries"),
        "dependencies" if name == "packages.lock.json" else "libraries",
    )
    if len(matches) >= DEPENDENCY_MATCH_LOOKAHEAD:
        return matches
    if isinstance(groups, dict):
        for target, packages in groups.items():
            if extend_matches(matches, json_dependency_keys(packages, f"{field}.{target}")):
                return matches
    return matches


def scoped_dependency_matches(text: str, name: str) -> list[dict] | None:
    parsers = {
        "setup.py": python_setup_dependency_matches,
        "setup.cfg": python_setup_cfg_dependency_matches,
        "pipfile": python_toml_dependency_matches,
        "pipfile.lock": python_lock_dependency_matches,
    }
    if parser := parsers.get(name):
        return parser(text)
    if name.startswith("requirements") and name.endswith((".txt", ".in")):
        return python_requirement_matches(text)
    if name == "packages.lock.json" or name.endswith(".deps.json"):
        return dotnet_json_dependency_matches(text, name)
    if name == "packages.config" or name.endswith(
        (".csproj", ".fsproj", ".vbproj", ".props", ".targets", ".nuspec")
    ):
        return dotnet_xml_dependency_matches(text, name)
    return None
