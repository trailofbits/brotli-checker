import tracemalloc

import brotli_source_leads as leads
import pytest


def test_many_string_tokens_do_not_require_a_full_token_index():
    source = "'';\n" * 50000 + "import brotli\n"
    tracemalloc.start()
    try:
        matches, truncated = leads.source_references(source, ".py")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert matches[0]["line"] == 50001
    assert not truncated
    assert peak < len(source) * 4


@pytest.mark.parametrize(
    ("suffix", "source"),
    [
        (".rb", "text = <<~NOTE\nBrotli.inflate(payload)\nNOTE\n"),
        (".rb", "=begin\nBrotli.inflate(payload)\n=end\n"),
        (".php", "$text = <<<'NOTE'\nbrotli_uncompress($payload);\nNOTE;\n"),
        (".php", "$text = <<<NOTE\nbrotli_uncompress($payload);\nNOTE;\n"),
        (".js", "const s = `zlib.brotliDecompress(payload)`;"),
        (".js", r"const s = `\${zlib.brotliDecompress(payload)}`;"),
        (".js", 'const s = `${"zlib.brotliDecompress(payload)"}`;'),
        (".js", "const s = `${/* zlib.brotliDecompress(payload) */ 1}`;"),
    ],
)
def test_heredoc_comments_and_template_literal_prose_are_not_calls(suffix, source):
    assert leads.source_references(source, suffix) == ([], False)


@pytest.mark.parametrize(
    "source",
    [
        "const s = `decoded: ${zlib.brotliDecompress(payload)}`;",
        "const s = `decoded: ${{value: zlib.brotliDecompress(payload)}.value}`;",
        'const s = `quoted: ${"}" + zlib.brotliDecompress(payload)}`;',
    ],
)
def test_executable_template_expressions_preserve_source_locations(source):
    matches, truncated = leads.source_references(source, ".js")
    assert len(matches) == 1
    assert matches[0]["signal"] == "node_zlib_brotli_api"
    assert matches[0]["column"] == source.index("zlib.brotliDecompress") + 1
    assert matches[0]["text"] == source
    assert not truncated


@pytest.mark.parametrize(
    ("suffix", "source", "signal"),
    [
        (
            ".go",
            (
                "func decodeBlockTypeAndLength(s *Reader) bool {}\n"
                "func decodeLiteralBlockSwitch(s *Reader) {}"
            ),
            "go_port_decoder_source",
        ),
        (
            ".rs",
            "fn DecodeBlockTypeAndLength<T>() {}\nfn BrotliDecompressStream<T>() {}",
            "rust_port_decoder_source",
        ),
    ],
)
def test_modified_port_implementation_has_no_implicit_patch_verdict(suffix, source, signal):
    matches, truncated = leads.source_references(source, suffix)
    assert len(matches) == 1
    assert matches[0]["signal"] == signal
    assert "patch_status" not in matches[0]
    assert not truncated


@pytest.mark.parametrize(
    ("suffix", "source", "signal", "ecosystem"),
    [
        (
            ".ts",
            "import { brotliDecompress as decode } from 'node:zlib';",
            "node_zlib_brotli_import",
            "node_zlib",
        ),
        (
            ".js",
            "const { createBrotliDecompress: make } = require('zlib');",
            "node_zlib_brotli_import",
            "node_zlib",
        ),
        (
            ".mjs",
            "const output = zlib.brotliDecompressSync(input);",
            "node_zlib_brotli_api",
            "node_zlib",
        ),
        (
            ".js",
            "const stream = new DecompressionStream('brotli');",
            "web_brotli_decompression_stream",
            "web_compression_streams",
        ),
        (
            ".ts",
            "import brotliPromise from 'brotli-wasm';",
            "brotli_wasm_import",
            "brotli-wasm",
        ),
        (
            ".js",
            "const module = await import('brotli-dec-wasm/web');",
            "brotli_dec_wasm_import",
            "brotli-dec-wasm",
        ),
        (
            ".mts",
            "import { decompress } from '@nick/brotli';",
            "nick_brotli_wasm_import",
            "@nick/brotli",
        ),
        (
            ".cjs",
            "const codec = require('wasm-brotli');",
            "wasm_brotli_import",
            "wasm-brotli",
        ),
        (
            ".tsx",
            "import { load } from '@wasm-zoo/brotli';",
            "wasm_zoo_brotli_import",
            "@wasm-zoo/brotli",
        ),
        (
            ".js",
            "const decompress = require('brotli/decompress');",
            "brotli_javascript_import",
            "brotli_js",
        ),
        (
            ".js",
            "import { decompress } from 'brotli-compress';",
            "brotli_compress_import",
            "brotli-compress",
        ),
        (
            ".js",
            "const wasm = new URL('./brotli_decoder_bg.wasm?url', import.meta.url);",
            "brotli_wasm_asset",
            "webassembly_asset",
        ),
        (
            ".py",
            "import brotli as selected_brotli",
            "python_brotli_import",
            "python_brotli",
        ),
        (
            ".py",
            "import sys, brotli as selected_brotli",
            "python_brotli_import",
            "python_brotli",
        ),
        (
            ".pyi",
            "from brotlicffi import Decompressor as Decoder",
            "python_brotlicffi_import",
            "python_brotlicffi",
        ),
        (
            ".py",
            "provider = ctypes.CDLL('libbrotlidec.so.1')",
            "python_brotlidec_library_load",
            "python_native_brotli_ffi",
        ),
        (
            ".py",
            'ffi.cdef("int BrotliDecoderDecompressStream(void *state);")',
            "python_brotli_cdef",
            "python_native_brotli_ffi",
        ),
        (
            ".java",
            "import com.aayushatharva.brotli4j.decoder.BrotliInputStream;",
            "brotli4j_import",
            "brotli4j",
        ),
        (
            ".kt",
            "import org.brotli.dec.BrotliInputStream",
            "java_brotli_port_import",
            "org.brotli.dec",
        ),
        (
            ".java",
            'System.loadLibrary("brotlidec");',
            "jvm_brotlidec_library_load",
            "jvm_native_brotli_ffi",
        ),
        (
            ".java",
            'BrotliApi api = Native.load("libbrotlidec.so", BrotliApi.class);',
            "jvm_brotlidec_library_load",
            "jvm_native_brotli_ffi",
        ),
        (
            ".cs",
            "var decoder = new System.IO.Compression.BrotliStream(input, mode);",
            "dotnet_brotli_fully_qualified_type",
            "dotnet_brotli",
        ),
        (
            ".cs",
            "using System.IO.Compression;\nvar decoder = new BrotliDecoder();",
            "dotnet_brotli_imported_type",
            "dotnet_brotli",
        ),
        (
            ".cs",
            (
                "handler.AutomaticDecompression = DecompressionMethods.GZip | "
                "DecompressionMethods.Brotli;"
            ),
            "dotnet_automatic_brotli",
            "dotnet_http_decompression",
        ),
        (
            ".cs",
            '[DllImport("brotlidec")] static extern int BrotliDecoderDecompress();',
            "dotnet_brotlidec_library_import",
            "dotnet_native_brotli_ffi",
        ),
        (
            ".rs",
            "use brotli2::read::BrotliDecoder;",
            "rust_native_brotli_crate",
            "rust_native_brotli_wrapper",
        ),
        (
            ".rs",
            "use brotli_decompressor::Decompressor;",
            "rust_brotli_port_crate",
            "rust_brotli_port",
        ),
        (
            ".rs",
            "let decoder = brotli::Decompressor::new(input, 4096);",
            "rust_brotli_port_crate",
            "rust_brotli_port",
        ),
        (
            ".rs",
            '#[link(name = "brotlidec")]\nextern "C" {}',
            "rust_brotlidec_link",
            "rust_system_brotli_ffi",
        ),
        (
            ".rs",
            'println!("cargo:rustc-link-lib=brotlidec");',
            "rust_brotlidec_build_link",
            "rust_system_brotli_ffi",
        ),
        (
            ".rs",
            'pkg_config::Config::new().probe("libbrotlidec").unwrap();',
            "rust_brotlidec_pkg_config",
            "rust_system_brotli_ffi",
        ),
        (
            ".go",
            'import (\n  cb "github.com/google/brotli/go/cbrotli"\n)',
            "go_cbrotli_import",
            "go_cbrotli",
        ),
        (
            ".go",
            'import brotli "github.com/andybalholm/brotli"',
            "go_brotli_port_import",
            "go_brotli_port",
        ),
        (
            ".go",
            "result := C.BrotliDecoderDecompressStream(state, a, b, c, d, e)",
            "go_brotli_c_api",
            "go_cgo_brotli",
        ),
        (
            ".rb",
            "require 'brotli'\noutput = Brotli.inflate(input)",
            "ruby_brotli_require",
            "ruby_brotli",
        ),
        (
            ".php",
            "$output = brotli_uncompress($input);",
            "php_brotli_api",
            "php_ext_brotli",
        ),
        (
            ".ini",
            "extension=brotli.so",
            "php_brotli_extension",
            "php_ext_brotli",
        ),
        (
            ".wat",
            '(import "env" "BrotliDecoderDecompressStream" (func $decode))',
            "wasm_brotli_c_api",
            "webassembly_c_api",
        ),
    ],
)
def test_language_scoped_source_leads(suffix, source, signal, ecosystem):
    matches, truncated = leads.source_references(source, suffix)
    assert truncated is False
    assert any(row["signal"] == signal and row["ecosystem"] == ecosystem for row in matches)
    assert all(row["implementation_hint"] for row in matches)


def test_go_cgo_preamble_directives_are_intentionally_collected_from_comments():
    source = """package decoder
/*
#cgo pkg-config: libbrotlicommon libbrotlidec
#include <brotli/decode.h>
*/
import "C"
"""
    matches, truncated = leads.source_references(source, ".go")
    assert truncated is False
    assert [row["signal"] for row in matches] == [
        "go_brotlidec_pkg_config",
        "go_brotli_header",
    ]
    assert [row["line"] for row in matches] == [3, 4]


def test_go_single_line_cgo_preamble_directives_are_collected_but_docs_are_not():
    source = """package decoder
// #cgo pkg-config: libbrotlicommon libbrotlidec libbrotlienc
// #include <brotli/decode.h>
import "C"
"""
    matches, truncated = leads.source_references(source, ".go")
    assert truncated is False
    assert [row["signal"] for row in matches] == [
        "go_brotlidec_pkg_config",
        "go_brotli_header",
    ]
    assert [row["line"] for row in matches] == [2, 3]

    docs = "// docs: #cgo pkg-config: libbrotlidec\n// example: #include <brotli/decode.h>\n"
    assert leads.source_references(docs, ".go") == ([], False)


def test_go_import_block_has_no_arbitrary_byte_window():
    imports = "\n".join(f'  _ "example.invalid/dependency{index}"' for index in range(80))
    source = f'import (\n{imports}\n  cb "github.com/google/brotli/go/cbrotli"\n)\n'
    matches, truncated = leads.source_references(source, ".go")
    assert truncated is False
    assert [row["signal"] for row in matches] == ["go_cbrotli_import"]


def test_go_import_block_ignores_commented_path_and_finds_later_real_import():
    commented = """import (
  // cb "github.com/google/brotli/go/cbrotli"
  "fmt"
)
"""
    assert leads.source_references(commented, ".go") == ([], False)

    genuine = commented + 'import cb "github.com/google/brotli/go/cbrotli"\n'
    matches, truncated = leads.source_references(genuine, ".go")
    assert truncated is False
    assert [row["signal"] for row in matches] == ["go_cbrotli_import"]
    assert matches[0]["line"] == 5


@pytest.mark.parametrize(
    ("suffix", "source"),
    [
        (
            ".js",
            (
                "// import x from 'brotli-wasm'\n"
                'const docs = "new DecompressionStream(\\"brotli\\")";\n'
                "const decompress = value => value;"
            ),
        ),
        (".py", "# import brotli\ndocs = 'import brotlicffi as decoder'"),
        (
            ".java",
            '// import com.aayushatharva.brotli4j.decoder.Decoder;\nString s = "org.brotli.dec";',
        ),
        (".cs", '// System.IO.Compression.BrotliStream\nvar docs = "BrotliDecoder";'),
        (".rs", '// #[link(name = "brotlidec")]\nlet docs = "use brotli2::read";'),
        (
            ".go",
            (
                '// import cb "github.com/google/brotli/go/cbrotli"\n'
                'var docs = "C.BrotliDecoderDecompress"'
            ),
        ),
        (".rb", "# require 'brotli'\ndocs = 'Brotli.inflate(input)'"),
        (".php", '// brotli_uncompress($input);\n$docs = "brotli_uncompress_init()";'),
        (".ini", "; extension=brotli.so"),
        (".wat", ';; BrotliDecoderDecompressStream\n(data (i32.const 0) "BrotliDecoderVersion")'),
    ],
)
def test_comment_and_unrelated_literal_mentions_are_not_leads(suffix, source):
    assert leads.source_references(source, suffix) == ([], False)


@pytest.mark.parametrize("suffix", [".json", ".md", ".txt", ".js.map", ".wasm", "js"])
def test_suffix_boundaries_reject_non_source_inputs(suffix):
    source = "import brotliPromise from 'brotli-wasm';"
    assert leads.source_references(source, suffix) == ([], False)


def test_generic_decoder_and_http_names_are_not_seeded():
    source = """
const output = decompress(input);
client.fetch(url);
WebAssembly.instantiate(bytes);
const headers = { 'Accept-Encoding': 'br' };
"""
    assert leads.source_references(source, ".js") == ([], False)


def test_short_dotnet_type_requires_the_runtime_namespace_import():
    assert leads.source_references("new BrotliStream(input, mode);", ".cs") == ([], False)


def test_locations_are_source_ordered_and_output_is_bounded():
    source = "// heading\n" + "\n".join(
        f"import codec{i} from 'brotli-wasm';" for i in range(leads.MAX_SOURCE_MATCHES + 5)
    )
    matches, truncated = leads.source_references(source, ".js")
    assert truncated is True
    assert len(matches) == leads.MAX_SOURCE_MATCHES
    assert [row["line"] for row in matches[:3]] == [2, 3, 4]
    assert all(row["column"] == 1 for row in matches)
    assert all(len(row["text"]) <= leads.MAX_MATCH_TEXT for row in matches)


def test_multiple_ecosystems_preserve_exact_locations_and_alias_import_leads():
    source = (
        "import brotliPromise from 'brotli-wasm';\n"
        "const brotli = await brotliPromise;\n"
        "const native = zlib.brotliDecompressSync(input);\n"
        'const stream = new DecompressionStream("brotli");\n'
    )
    matches, truncated = leads.source_references(source, ".ts")
    assert truncated is False
    assert [(row["line"], row["column"], row["signal"]) for row in matches] == [
        (1, 1, "brotli_wasm_import"),
        (3, 16, "node_zlib_brotli_api"),
        (4, 16, "web_brotli_decompression_stream"),
    ]


@pytest.mark.parametrize(
    ("suffix", "source", "signal"),
    [
        (
            ".py",
            "codec = importlib.import_module('brotli')",
            "python_brotli_dynamic_import",
        ),
        (
            ".py",
            'codec = importlib.import_module("brotlicffi")',
            "python_brotlicffi_dynamic_import",
        ),
        (
            ".py",
            "from ctypes import c_int, CDLL\ncodec = CDLL('libbrotlidec.so.1')",
            "python_brotlidec_imported_cdll",
        ),
        (
            ".cs",
            (
                '[DllImport("renamed_codec", EntryPoint = "BrotliDecoderDecompress")]\n'
                "private static extern int Decode();"
            ),
            "dotnet_brotli_entrypoint_import",
        ),
        (
            ".cs",
            "services.AddRequestDecompression();",
            "dotnet_request_decompression_registration",
        ),
    ],
)
def test_precise_dynamic_and_native_source_leads(suffix, source, signal):
    matches, truncated = leads.source_references(source, suffix)
    assert truncated is False
    assert [row["signal"] for row in matches] == [signal]


@pytest.mark.parametrize(
    ("suffix", "source"),
    [
        (".py", "codec = loader.import_module('brotli')"),
        (
            ".py",
            (
                "# importlib.import_module('brotli')\n"
                "docs = \"importlib.import_module('brotlicffi')\""
            ),
        ),
        (".py", "codec = CDLL('libbrotlidec.so.1')"),
        (".py", "from ctypes import CDLL as load\ncodec = load('libbrotlidec.so.1')"),
        (".cs", '[DllImport("renamed_codec")] private static extern int Decode();'),
        (
            ".cs",
            '// [DllImport("renamed_codec", EntryPoint="BrotliDecoderDecompress")]\n',
        ),
        (".cs", 'var docs = "services.AddRequestDecompression();";'),
        (".cs", "services.AddRequestDecompressionFactory();"),
    ],
)
def test_dynamic_and_native_lookalikes_are_not_source_leads(suffix, source):
    assert leads.source_references(source, suffix) == ([], False)
