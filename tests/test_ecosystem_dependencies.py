import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts"
sys.path.insert(0, str(SCRIPTS))
import brotli_dependencies as dependencies  # noqa: E402


@pytest.mark.parametrize(
    ("name", "text", "expected_text"),
    [
        ("gemfile", "gem 'brotli', '~> 0.8'", "gem 'brotli', '~> 0.8'"),
        ("gemfile", 'gem("brotli")', 'gem("brotli")'),
        (
            "service.gemspec",
            'spec.add_dependency "brotli", ">= 0.8"',
            'spec.add_dependency "brotli", ">= 0.8"',
        ),
        (
            "service.gemspec",
            "add_runtime_dependency('brotli')",
            "add_runtime_dependency('brotli')",
        ),
    ],
)
def test_ruby_dependencies_are_extracted_from_calls(name, text, expected_text):
    assert dependencies.dependency_matches(text, name) == [{"line": 1, "text": expected_text}]


def test_ruby_lock_finds_direct_and_transitive_packages_only_in_dependency_sections():
    text = """GEM
  remote: https://rubygems.org/
  specs:
    wrapper (1.0.0)
      brotli (~> 0.8)
    brotli (0.8.0)

DEPENDENCIES
  brotli

BUNDLED WITH
   2.7.1
"""
    assert dependencies.dependency_matches(text, "gemfile.lock") == [
        {"line": 5, "text": "      brotli (~> 0.8)"},
        {"line": 6, "text": "    brotli (0.8.0)"},
        {"line": 9, "text": "  brotli"},
    ]


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("gemfile", "# gem 'brotli'\nsource 'https://brotli.example.invalid'"),
        ("service.gemspec", 'spec.summary = "A Brotli security checker"'),
        ("service.gemspec", 'spec.add_development_dependency "brotli"'),
        ("gemfile.lock", "NOTES\n  brotli (is discussed here)\n"),
    ],
)
def test_ruby_prose_comments_and_development_helpers_are_not_dependencies(name, text):
    assert dependencies.dependency_matches(text, name) == []


def test_ruby_block_comments_are_not_dependencies():
    text = '=begin\ngem "brotli"\n=end\ngem "zlib"\n'
    assert dependencies.dependency_matches(text, "gemfile") == []


def test_composer_project_dependencies_are_extracted_from_package_keys():
    text = """{
  "name": "example/app",
  "description": "Brotli benchmark results",
  "require": {"ext-brotli": "*", "php": ">=8.1"},
  "provide": {"vendor/brotli-adapter": "1.0"},
  "scripts": {"check": "echo brotli"}
}"""
    assert dependencies.dependency_matches(text, "composer.json") == [
        {"field": "require.ext-brotli", "text": '"*"'},
        {"field": "provide.vendor/brotli-adapter", "text": '"1.0"'},
    ]


def test_composer_lock_finds_transitive_names_requirements_and_platform_extensions():
    text = """{
  "packages": [
    {"name": "vendor/native-codec", "require": {"ext-brotli": "*"}},
    {"name": "vendor/brotli-wrapper", "description": "native wrapper"}
  ],
  "packages-dev": [{"name": "vendor/test-helper", "require": {"brotli/tool": "^1"}}],
  "platform": {"ext-brotli": "*"}
}"""
    assert dependencies.dependency_matches(text, "composer.lock") == [
        {"field": "platform.ext-brotli", "text": '"*"'},
        {"field": "packages[0].require.ext-brotli", "text": '"*"'},
        {"field": "packages[1].name", "text": "vendor/brotli-wrapper"},
        {"field": "packages-dev[0].require.brotli/tool", "text": '"^1"'},
    ]


@pytest.mark.parametrize(
    "text",
    [
        '{"name":"example/app","description":"Brotli security checker"}',
        '{"name":"example/app","scripts":{"test":"echo brotli"}}',
        '{"packages":[{"name":"vendor/app","description":"Uses Brotli when available"}]}',
    ],
)
def test_composer_descriptions_and_scripts_are_not_dependencies(text):
    name = "composer.lock" if "packages" in text else "composer.json"
    assert dependencies.dependency_matches(text, name) == []


def test_composer_conflict_does_not_claim_the_forbidden_package_is_selected():
    text = '{"conflict":{"ext-brotli":"*"},"require":{"php":">=8.1"}}'
    assert dependencies.dependency_matches(text, "composer.json") == []


def test_malformed_composer_metadata_preserves_an_explicit_bounded_lead():
    assert dependencies.dependency_matches('{"require":{"ext-brotli":', "composer.json") == [
        {"text": "Unparseable Composer metadata mentioning Brotli-related components."}
    ]
    assert dependencies.dependency_matches('{"require":{"ext-zlib":', "composer.json") == []
    assert dependencies.dependency_matches('["ext-brotli"]', "composer.lock") == [
        {"text": "Unexpected Composer metadata mentioning Brotli-related components."}
    ]


def test_generic_and_composer_match_populations_stop_at_one_row_of_lookahead():
    count = dependencies.DEPENDENCY_MATCH_LOOKAHEAD
    requirements = "\n".join(f"brotli-package-{index}" for index in range(200_000))
    assert len(dependencies.dependency_matches(requirements, "requirements.txt")) == count

    gemfile = "\n".join(f"gem 'brotli-{index}'" for index in range(100))
    assert len(dependencies.dependency_matches(gemfile, "gemfile")) == count

    generic = "\n".join(f"brotli-{index}" for index in range(100))
    assert len(dependencies.dependency_matches(generic, "package.json")) == count

    composer = (
        '{"require":{' + ",".join(f'"vendor/brotli-{index}":"*"' for index in range(100)) + "}}"
    )
    assert len(dependencies.dependency_matches(composer, "composer.json")) == count
