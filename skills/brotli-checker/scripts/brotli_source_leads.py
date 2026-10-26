"""Bounded, language-scoped Brotli source leads without target execution."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import cache
from heapq import merge
from io import StringIO
from itertools import islice
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator

MAX_SOURCE_MATCHES = 20
MAX_MATCH_TEXT = 300

JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts"})
JVM_SUFFIXES = frozenset({".java", ".kt", ".kts", ".groovy", ".scala"})
DOTNET_SUFFIXES = frozenset({".cs"})
RUBY_SUFFIXES = frozenset({".rb", ".rake", ".gemspec"})
PHP_SUFFIXES = frozenset({".php", ".phtml", ".inc"})


@dataclass(frozen=True)
class LeadRule:
    signal: str
    suffixes: frozenset[str]
    pattern: str
    ecosystem: str
    implementation_hint: str
    requires: str | None = None
    include_comments: bool = False


def _js_import(package: str) -> str:
    return (
        r"(?:\bimport\s*(?:(?:[^;'\"\r\n]+?\s+from\s+)?|\(\s*)|"
        r"\brequire\s*\(\s*)"
        rf"['\"]{package}(?:/[^'\"\\\r\n]*)?['\"]"
    )


def _python_import(module: str) -> str:
    name = re.escape(module)
    return (
        rf"\b(?:from\s+{name}\b\s+import\b|import\s+"
        rf"(?:[A-Za-z_]\w*(?:\s+as\s+[A-Za-z_]\w*)?\s*,\s*)*{name}\b)"
    )


NODE_API = (
    r"(?:brotliDecompress(?:Sync)?|createBrotliDecompress|BrotliDecompress|"
    r"decompressBrotli(?:Sync)?)"
)

RULES = (
    LeadRule(
        "go_port_decoder_source",
        frozenset({".go"}),
        r"\bfunc\s+decodeBlockTypeAndLength\s*\(",
        "andybalholm_brotli_source",
        "Go decoder implementation source; modified bytes require independent patch review",
        requires=r"\bfunc\s+decodeLiteralBlockSwitch\s*\(",
    ),
    LeadRule(
        "rust_port_decoder_source",
        frozenset({".rs"}),
        r"\bfn\s+DecodeBlockTypeAndLength\s*[<(]",
        "rust_brotli_decompressor_source",
        "Rust decoder implementation source; modified bytes require independent patch review",
        requires=r"\bfn\s+BrotliDecompressStream\s*[<(]",
    ),
    LeadRule(
        "node_zlib_brotli_import",
        JS_SUFFIXES,
        rf"(?:\bimport\s*\{{[^}}\r\n]*\b{NODE_API}\b[^}}\r\n]*\}}\s*from\s*"
        rf"['\"](?:node:)?zlib(?:/iter)?['\"]|"
        rf"\b(?:const|let|var)\s*\{{[^}}\r\n]*\b{NODE_API}\b[^}}\r\n]*\}}\s*=\s*"
        rf"require\s*\(\s*['\"](?:node:)?zlib(?:/iter)?['\"]\s*\))",
        "node_zlib",
        "Node-compatible runtime Brotli API; resolve the actual runtime and bundled provider",
    ),
    LeadRule(
        "node_zlib_brotli_api",
        JS_SUFFIXES,
        rf"\b(?:new\s+)?(?:[A-Za-z_$][\w$]*\s*(?:\?\.)?\s*\.\s*)?{NODE_API}\b\s*\(",
        "node_zlib",
        "Node-compatible runtime Brotli API; resolve the actual runtime and bundled provider",
    ),
    LeadRule(
        "web_brotli_decompression_stream",
        JS_SUFFIXES,
        r"\bnew\s+DecompressionStream\s*\(\s*['\"]brotli['\"]",
        "web_compression_streams",
        "Runtime-provided Brotli decoder; browser, Node, Bun, and other runtimes can differ",
    ),
    LeadRule(
        "brotli_wasm_import",
        JS_SUFFIXES,
        _js_import(r"brotli-wasm"),
        "brotli-wasm",
        (
            "Expected Rust implementation compiled to WebAssembly; resolve the selected "
            "package and shipped .wasm"
        ),
    ),
    LeadRule(
        "brotli_dec_wasm_import",
        JS_SUFFIXES,
        _js_import(r"brotli-dec-wasm"),
        "brotli-dec-wasm",
        "Expected Rust brotli-decompressor port compiled to WebAssembly; resolve the shipped .wasm",
    ),
    LeadRule(
        "nick_brotli_wasm_import",
        JS_SUFFIXES,
        _js_import(r"@nick/brotli"),
        "@nick/brotli",
        "Expected Rust brotli-decompressor port compiled to WebAssembly; resolve the shipped .wasm",
    ),
    LeadRule(
        "wasm_brotli_import",
        JS_SUFFIXES,
        _js_import(r"wasm-brotli"),
        "wasm-brotli",
        (
            "Expected Rust implementation compiled to WebAssembly; resolve package "
            "provenance and shipped .wasm"
        ),
    ),
    LeadRule(
        "wasm_zoo_brotli_import",
        JS_SUFFIXES,
        _js_import(r"@wasm-zoo/brotli"),
        "@wasm-zoo/brotli",
        (
            "Expected Google Brotli C CLI compiled to WebAssembly; resolve the package "
            "release and shipped .wasm"
        ),
    ),
    LeadRule(
        "brotli_javascript_import",
        JS_SUFFIXES,
        _js_import(r"brotli"),
        "brotli_js",
        "Expected hand-ported JavaScript decoder; Google C decoder status does not transfer",
    ),
    LeadRule(
        "brotli_compress_import",
        JS_SUFFIXES,
        _js_import(r"brotli-compress"),
        "brotli-compress",
        (
            "Package can select WebAssembly or a JavaScript port; resolve the imported "
            "entry point and artifact"
        ),
    ),
    LeadRule(
        "brotli_wasm_asset",
        JS_SUFFIXES,
        r"(?:\bfrom\s+|\b(?:import|require)\s*(?:\(\s*)?|\bnew\s+URL\s*\(\s*)"
        r"['\"][^'\"\r\n]*brotli[^'\"\r\n]*\.wasm(?:[?#][^'\"\r\n]*)?['\"]",
        "webassembly_asset",
        "Brotli-named WebAssembly asset; implementation and bundled source revision are unresolved",
    ),
    LeadRule(
        "python_brotli_import",
        frozenset({".py", ".pyi"}),
        _python_import("brotli"),
        "python_brotli",
        (
            "Expected CPython native extension; resolve the installed distribution, build "
            "mode, and provider"
        ),
    ),
    LeadRule(
        "python_brotlicffi_import",
        frozenset({".py", ".pyi"}),
        _python_import("brotlicffi"),
        "python_brotlicffi",
        (
            "Expected CFFI/native Brotli binding; resolve bundled versus shared provider "
            "and installed build"
        ),
    ),
    LeadRule(
        "python_brotli_dynamic_import",
        frozenset({".py", ".pyi"}),
        r"\bimportlib\s*\.\s*import_module\s*\(\s*['\"]brotli['\"]",
        "python_brotli",
        (
            "Dynamic import of the expected CPython native extension; resolve the "
            "installed distribution, build mode, and provider"
        ),
    ),
    LeadRule(
        "python_brotlicffi_dynamic_import",
        frozenset({".py", ".pyi"}),
        r"\bimportlib\s*\.\s*import_module\s*\(\s*['\"]brotlicffi['\"]",
        "python_brotlicffi",
        (
            "Dynamic import of the expected CFFI/native binding; resolve bundled "
            "versus shared provider and installed build"
        ),
    ),
    LeadRule(
        "python_brotlidec_library_load",
        frozenset({".py", ".pyi"}),
        r"\b(?:ctypes\.(?:CDLL|PyDLL)|ctypes\.cdll\.LoadLibrary|[A-Za-z_]\w*\.dlopen)"
        r"\s*\(\s*['\"][^'\"\r\n]*(?:lib)?brotlidec(?:\.[^'\"\r\n]*)?['\"]",
        "python_native_brotli_ffi",
        "Literal native libbrotlidec load; resolve the deployed library and exact FFI calls",
    ),
    LeadRule(
        "python_brotlidec_imported_cdll",
        frozenset({".py", ".pyi"}),
        r"\bCDLL\s*\(\s*['\"][^'\"\r\n]*(?:lib)?brotlidec(?:\.[^'\"\r\n]*)?['\"]",
        "python_native_brotli_ffi",
        "Imported ctypes CDLL loads libbrotlidec; resolve the deployed library and FFI calls",
        requires=(
            r"\bfrom\s+ctypes\s+import\s+(?:\(\s*)?"
            r"(?:[A-Za-z_]\w*(?:\s+as\s+[A-Za-z_]\w*)?\s*,\s*)*CDLL\b(?!\s+as\b)"
        ),
    ),
    LeadRule(
        "python_brotli_cdef",
        frozenset({".py", ".pyi"}),
        r"\b[A-Za-z_]\w*\.cdef\s*\(\s*[rRuUbBfF]*"
        r"(?:'''[\s\S]*?\bBrotliDecoder(?:CreateInstance|DestroyInstance|"
        r"Decompress(?:Stream)?|Version)\b[\s\S]*?'''|"
        r"\"\"\"[\s\S]*?\bBrotliDecoder(?:CreateInstance|DestroyInstance|"
        r"Decompress(?:Stream)?|Version)\b[\s\S]*?\"\"\"|"
        r"['\"][^'\"\r\n]*\bBrotliDecoder(?:CreateInstance|DestroyInstance|"
        r"Decompress(?:Stream)?|Version)\b[^'\"\r\n]*['\"])",
        "python_native_brotli_ffi",
        "CFFI declares a Brotli C ABI symbol; resolve the loaded library and provider",
    ),
    LeadRule(
        "foreign_brotli_c_api",
        JS_SUFFIXES
        | JVM_SUFFIXES
        | DOTNET_SUFFIXES
        | RUBY_SUFFIXES
        | PHP_SUFFIXES
        | frozenset({".py", ".pyi", ".rs", ".go"}),
        r"\bBrotliDecoder(?:CreateInstance|DestroyInstance|Decompress(?:Stream)?|Version)\b\s*\(",
        "foreign_brotli_c_api",
        (
            "Brotli C ABI name in non-C source; ABI-compatible ports can expose it, so "
            "resolve the provider"
        ),
    ),
    LeadRule(
        "brotli4j_import",
        JVM_SUFFIXES,
        r"\b(?:import\s+)?com\.aayushatharva\.brotli4j(?:\.[A-Za-z_$*][\w$*]*)+",
        "brotli4j",
        (
            "Expected JNI wrapper with a platform-native artifact; resolve classifier and "
            "extracted provider"
        ),
    ),
    LeadRule(
        "java_brotli_port_import",
        JVM_SUFFIXES,
        r"\b(?:import\s+)?org\.brotli\.dec(?:\.[A-Za-z_$*][\w$*]*)+",
        "org.brotli.dec",
        "Expected Java decoder port; Google C decoder status does not transfer",
    ),
    LeadRule(
        "jvm_brotlidec_library_load",
        JVM_SUFFIXES,
        r"\b(?:System\.load(?:Library)?|(?:[A-Za-z_$][\w$]*\.)?Native\.load)"
        r"\s*\(\s*['\"][^'\"\r\n]*(?:lib)?brotlidec(?:\.[^'\"\r\n]*)?['\"]",
        "jvm_native_brotli_ffi",
        "Literal native libbrotlidec load; resolve JNI/JNA binding and deployed provider",
    ),
    LeadRule(
        "dotnet_brotli_fully_qualified_type",
        DOTNET_SUFFIXES,
        r"\bSystem\.IO\.Compression\.(?:BrotliStream|BrotliDecoder)\b",
        "dotnet_brotli",
        (
            ".NET runtime Brotli API; resolve framework-dependent, self-contained, or "
            "NativeAOT deployment"
        ),
    ),
    LeadRule(
        "dotnet_brotli_imported_type",
        DOTNET_SUFFIXES,
        r"\b(?:BrotliStream|BrotliDecoder)\b",
        "dotnet_brotli",
        (
            ".NET runtime Brotli API; resolve framework-dependent, self-contained, or "
            "NativeAOT deployment"
        ),
        requires=r"\busing\s+System\.IO\.Compression\s*;",
    ),
    LeadRule(
        "dotnet_automatic_brotli",
        DOTNET_SUFFIXES,
        r"\bAutomaticDecompression\s*=\s*[^;\r\n]*\bDecompressionMethods\.(?:Brotli|All)\b",
        "dotnet_http_decompression",
        (
            ".NET HTTP automatic decompression explicitly includes Brotli; resolve the "
            "deployed runtime"
        ),
    ),
    LeadRule(
        "dotnet_brotlidec_library_import",
        DOTNET_SUFFIXES,
        r"\[\s*(?:DllImport|LibraryImport)\s*\(\s*['\"]"
        r"[^'\"\r\n]*(?:lib)?brotlidec(?:\.[^'\"\r\n]*)?['\"]",
        "dotnet_native_brotli_ffi",
        "Literal native libbrotlidec import; resolve the deployed library and ABI provider",
    ),
    LeadRule(
        "dotnet_brotli_entrypoint_import",
        DOTNET_SUFFIXES,
        r"\[\s*(?:DllImport|LibraryImport)(?:Attribute)?\s*\(\s*['\"][^'\"\r\n]+['\"]"
        r"[^\]]{0,500}\bEntryPoint\s*=\s*['\"]BrotliDecoder(?:CreateInstance|"
        r"DestroyInstance|Decompress(?:Stream)?|Version)['\"][^\]]{0,500}\)\s*\]",
        "dotnet_native_brotli_ffi",
        (
            "Brotli C ABI entry point imported from a renamed native library; ABI name "
            "does not establish the provider"
        ),
    ),
    LeadRule(
        "dotnet_request_decompression_registration",
        DOTNET_SUFFIXES,
        r"\bAddRequestDecompression\s*\(",
        "aspnet_request_decompression",
        (
            "ASP.NET request decompression is registered; resolve enabled providers, "
            "configuration, and deployed runtime"
        ),
    ),
    LeadRule(
        "rust_native_brotli_crate",
        frozenset({".rs"}),
        r"\b(?:use\s+(?:brotli2|brotlic)::|extern\s+crate\s+(?:brotli2|brotlic)\b|"
        r"(?:brotli2|brotlic)::)",
        "rust_native_brotli_wrapper",
        (
            "Expected wrapper around Google Brotli C; resolve crate features, vendored "
            "source, and final provider"
        ),
    ),
    LeadRule(
        "rust_brotli_port_crate",
        frozenset({".rs"}),
        r"\b(?:use\s+(?:brotli|brotli_decompressor|brotli_ffi)::|"
        r"extern\s+crate\s+(?:brotli|brotli_decompressor|brotli_ffi)\b|"
        r"(?:brotli|brotli_decompressor|brotli_ffi)::)",
        "rust_brotli_port",
        (
            "Expected Rust implementation or Rust FFI surface; Google C decoder status "
            "does not transfer"
        ),
    ),
    LeadRule(
        "rust_brotlidec_link",
        frozenset({".rs"}),
        r"#\s*\[\s*link\s*\(\s*name\s*=\s*['\"](?:brotlidec|brotlicommon)['\"]",
        "rust_system_brotli_ffi",
        "Direct native library selection; resolve the linked or deployed provider",
    ),
    LeadRule(
        "rust_brotlidec_build_link",
        frozenset({".rs"}),
        r"\b(?:println|print)!\s*\(\s*['\"]cargo:rustc-link-lib=(?:static=|dylib=)?brotlidec['\"]",
        "rust_system_brotli_ffi",
        (
            "Cargo build script selects libbrotlidec; resolve static archive or deployed "
            "shared provider"
        ),
    ),
    LeadRule(
        "rust_brotlidec_pkg_config",
        frozenset({".rs"}),
        r"\bpkg_config\b[^\r\n]{0,200}['\"](?:lib)?brotlidec['\"]",
        "rust_system_brotli_ffi",
        "pkg-config selects libbrotlidec; resolve the build record and deployed provider",
    ),
    LeadRule(
        "rust_brotli_c_api",
        frozenset({".rs"}),
        r"\bBrotliDecoder(?:CreateInstance|DestroyInstance|Decompress(?:Stream)?|Version)\b",
        "rust_system_brotli_ffi",
        (
            "Brotli C ABI name; ABI-compatible Rust ports can expose it, so resolve "
            "linkage and provider"
        ),
    ),
    LeadRule(
        "go_cbrotli_import",
        frozenset({".go"}),
        r"\bimport\s*(?:\([^)]*?|(?:[A-Za-z_][\w]*\s+)?)"
        r"['\"]github\.com/google/brotli/go/cbrotli['\"]",
        "go_cbrotli",
        "Google cgo wrapper selecting native Brotli libraries; resolve build and deployed provider",
    ),
    LeadRule(
        "go_brotli_port_import",
        frozenset({".go"}),
        r"\bimport\s*(?:\([^)]*?|(?:[A-Za-z_][\w]*\s+)?)"
        r"['\"]github\.com/andybalholm/brotli['\"]",
        "go_brotli_port",
        "Expected pure-Go decoder; Google C decoder status does not transfer",
    ),
    LeadRule(
        "go_brotli_c_api",
        frozenset({".go"}),
        r"\bC\.BrotliDecoder(?:CreateInstance|DestroyInstance|Decompress(?:Stream)?|Version)\b",
        "go_cgo_brotli",
        (
            "Brotli C ABI name through cgo; resolve whether the provider is Google C or "
            "compatible code"
        ),
    ),
    LeadRule(
        "go_brotlidec_pkg_config",
        frozenset({".go"}),
        r"^\s*(?://\s*)?#cgo\b[^\r\n]*(?:lib)?brotlidec\b",
        "go_cgo_brotli",
        "cgo selects libbrotlidec; resolve build record and deployed provider",
        include_comments=True,
    ),
    LeadRule(
        "go_brotli_header",
        frozenset({".go"}),
        r"^\s*(?://\s*)?#\s*include\s*[<\"]brotli/decode\.h[>\"]",
        "go_cgo_brotli",
        "cgo preamble includes the Google Brotli C decoder API",
        include_comments=True,
    ),
    LeadRule(
        "ruby_brotli_require",
        RUBY_SUFFIXES,
        r"\brequire(?:_relative)?\s*(?:\(\s*)?['\"]brotli['\"]",
        "ruby_brotli",
        (
            "Expected native Ruby extension; resolve vendored versus shared provider and "
            "installed gem build"
        ),
    ),
    LeadRule(
        "ruby_brotli_api",
        RUBY_SUFFIXES,
        r"\bBrotli(?:\.inflate|::(?:Reader|Decompressor))\b",
        "ruby_brotli",
        (
            "Expected native Ruby extension; resolve vendored versus shared provider and "
            "installed gem build"
        ),
    ),
    LeadRule(
        "php_brotli_api",
        PHP_SUFFIXES,
        r"\bbrotli_uncompress(?:_init|_add)?\s*\(",
        "php_ext_brotli",
        (
            "Expected native PHP extension; resolve loaded brotli.so and bundled versus "
            "shared provider"
        ),
    ),
    LeadRule(
        "php_brotli_extension",
        frozenset({".ini"}),
        r"(?i:^\s*extension\s*=\s*['\"]?brotli(?:\.so)?['\"]?\s*$)",
        "php_ext_brotli",
        "PHP configuration loads the native Brotli extension; resolve its build and provider",
    ),
    LeadRule(
        "wasm_brotli_c_api",
        frozenset({".wat", ".wast"}),
        r"\((?:import\s+\"[^\"]*\"\s+|export\s+)"
        r"\"BrotliDecoder(?:CreateInstance|DestroyInstance|Decompress(?:Stream)?|Version)\"",
        "webassembly_c_api",
        (
            "Google Brotli C API name in textual WebAssembly; resolve the originating "
            "source and binary"
        ),
    ),
)

RULE_BY_SIGNAL = {rule.signal: rule for rule in RULES}
ALL_SUFFIXES = frozenset(suffix for rule in RULES for suffix in rule.suffixes)

C_STYLE_TOKEN = re.compile(
    r"(?P<comment>//[^\n]*|/\*[\s\S]*?\*/)"
    r"|(?P<string>`(?:\\.|[^`\\])*`|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
)
HASH_TOKEN = re.compile(
    r"(?P<comment>\#[^\n]*)"
    r"|(?P<string>'''[\s\S]*?'''|\"\"\"[\s\S]*?\"\"\"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
)
RUBY_TOKEN = re.compile(
    r"(?P<comment>\#[^\n]*|(?m:^=begin\b)[\s\S]*?(?m:^=end\b[^\n]*(?:\n|$)|\Z))"
    r"|(?P<string><<[-~]?['\"]?(?P<ruby_label>[A-Za-z_]\w*)['\"]?[^\r\n]*\r?\n"
    r"[\s\S]*?(?m:^[ \t]*(?P=ruby_label)[ \t]*(?:\r?\n|$))"
    r"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
)
PHP_TOKEN = re.compile(
    r"(?P<comment>//[^\n]*|\#[^\n]*|/\*[\s\S]*?\*/)"
    r"|(?P<string><<<['\"]?(?P<php_label>[A-Za-z_]\w*)['\"]?\r?\n"
    r"[\s\S]*?(?m:^[ \t]*(?P=php_label);?[ \t]*(?:\r?\n|$))"
    r"|'(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")"
)
INI_TOKEN = re.compile(r"(?P<comment>[;#][^\n]*)|(?P<string>'[^']*'|\"[^\"]*\")")
WAT_TOKEN = re.compile(r"(?P<comment>;;[^\n]*|\(;[\s\S]*?;\))|(?P<string>\"(?:\\.|[^\"\\])*\")")


def _token_pattern(suffix: str) -> re.Pattern[str]:
    if suffix in {".py", ".pyi"}:
        return HASH_TOKEN
    if suffix in {".rb", ".rake", ".gemspec"}:
        return RUBY_TOKEN
    if suffix in {".php", ".phtml", ".inc"}:
        return PHP_TOKEN
    if suffix == ".ini":
        return INI_TOKEN
    if suffix in {".wat", ".wast"}:
        return WAT_TOKEN
    return C_STYLE_TOKEN


def _template_body_end(text: str, start: int) -> int:
    depth = 1
    cursor = start
    while cursor < len(text) - 1:
        token = C_STYLE_TOKEN.match(text, cursor)
        if token is not None:
            cursor = token.end()
            continue
        if text[cursor] == "{":
            depth += 1
        elif text[cursor] == "}":
            depth -= 1
            if depth == 0:
                return cursor
        cursor += 1
    return start


def _mask_template_literal(token: re.Match[str]) -> str:
    text = token.group()
    if token.lastgroup != "string" or not text.startswith("`"):
        return text
    output = StringIO()
    cursor = 0
    search = 1
    while (start := text.find("${", search)) >= 0:
        escape_start = start
        while escape_start and text[escape_start - 1] == "\\":
            escape_start -= 1
        search = start + 2
        if (start - escape_start) % 2:
            continue
        end = _template_body_end(text, search)
        if end == search:
            continue
        output.write(re.sub(r"[^\r\n]", " ", text[cursor:search]))
        output.write(text[search:end])
        cursor = end
        search = end + 1
    output.write(re.sub(r"[^\r\n]", " ", text[cursor:]))
    return output.getvalue()


def _mask_comments(text: str, suffix: str) -> str:
    output = StringIO()
    cursor = 0
    for token in _token_pattern(suffix).finditer(text):
        if token.lastgroup == "comment":
            start, end = token.span()
            output.write(text[cursor:start])
            output.write(re.sub(r"[^\r\n]", " ", text[start:end]))
            cursor = end
    if cursor == 0:
        return text
    output.write(text[cursor:])
    return output.getvalue()


@cache
def _lead_pattern(suffix: str, *, include_comments: bool) -> re.Pattern[str] | None:
    rules = [
        rule
        for rule in RULES
        if suffix in rule.suffixes and rule.include_comments == include_comments
    ]
    if not rules:
        return None
    return re.compile(
        "|".join(f"(?P<{rule.signal}>{rule.pattern})" for rule in rules),
        re.MULTILINE,
    )


def _classified_matches(
    pattern: re.Pattern[str], source: str, original: str, suffix: str
) -> Iterator[tuple[re.Match[str], str | None]]:
    tokens = _token_pattern(suffix).finditer(original)
    token = next(tokens, None)
    for match in pattern.finditer(source):
        while token is not None and token.end() <= match.start():
            token = next(tokens, None)
        kind = token.lastgroup if token is not None and token.start() <= match.start() else None
        yield match, kind


def _has_required_context(text: str, pattern: str, suffix: str) -> bool:
    return any(
        kind is None
        for _, kind in _classified_matches(re.compile(pattern, re.MULTILINE), text, text, suffix)
    )


@dataclass(frozen=True)
class SourceView:
    text: str
    code: str
    suffix: str
    requirements: dict[str, bool]


def _candidate_stream(
    view: SourceView,
    *,
    include_comments: bool,
) -> Iterator[tuple[int, int, LeadRule]]:
    pattern = _lead_pattern(view.suffix, include_comments=include_comments)
    if pattern is None:
        return
    source = view.text if include_comments else view.code
    for match, kind in _classified_matches(pattern, source, view.text, view.suffix):
        rule = RULE_BY_SIGNAL[match.lastgroup or ""]
        if include_comments:
            if kind != "comment":
                continue
        elif kind in {"comment", "string"}:
            continue
        if not view.requirements[rule.signal]:
            continue
        yield match.start(), match.end(), rule


def _candidates(text: str, suffix: str) -> list[tuple[int, int, LeadRule]]:
    lexical = C_STYLE_TOKEN.sub(_mask_template_literal, text) if suffix in JS_SUFFIXES else text
    code = _mask_comments(lexical, suffix)
    requirements = {
        rule.signal: rule.requires is None or _has_required_context(code, rule.requires, suffix)
        for rule in RULES
        if suffix in rule.suffixes
    }
    view = SourceView(lexical, code, suffix, requirements)
    streams = [
        islice(
            _candidate_stream(
                view,
                include_comments=include_comments,
            ),
            MAX_SOURCE_MATCHES + 1,
        )
        for include_comments in (False, True)
    ]
    candidates = []
    seen = set()
    for candidate in merge(*streams, key=lambda row: (row[0], row[1], row[2].signal)):
        key = (candidate[0], candidate[1], candidate[2].signal)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(candidate)
        if len(candidates) > MAX_SOURCE_MATCHES:
            break
    return candidates


def source_references(text: str, suffix: str) -> tuple[list[dict], bool]:
    """Return bounded heuristic source leads for one exact lowercase-able suffix."""
    normalized = suffix.lower()
    if normalized not in ALL_SUFFIXES:
        return [], False
    candidates = _candidates(text, normalized)
    matches = []
    for start, _, rule in candidates[:MAX_SOURCE_MATCHES]:
        line_start = text.rfind("\n", 0, start) + 1
        line_end = text.find("\n", start)
        matches.append(
            {
                "line": text.count("\n", 0, start) + 1,
                "column": start - line_start + 1,
                "signal": rule.signal,
                "ecosystem": rule.ecosystem,
                "implementation_hint": rule.implementation_hint,
                "text": text[
                    line_start : min(
                        line_end if line_end >= 0 else len(text), line_start + MAX_MATCH_TEXT
                    )
                ],
            }
        )
    return matches, len(candidates) > MAX_SOURCE_MATCHES
