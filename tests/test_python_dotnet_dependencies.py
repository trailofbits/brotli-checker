import sys
import tracemalloc
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1] / "skills/brotli-checker/scripts"
sys.path.insert(0, str(SCRIPTS))
import brotli_dependencies as dependencies  # noqa: E402


def test_requirement_sampling_does_not_split_the_entire_input_into_lines():
    text = "brotli\r\n" * 200000
    tracemalloc.start()
    try:
        rows = dependencies.dependency_matches(text, "requirements.txt")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert len(rows) == dependencies.DEPENDENCY_MATCH_LOOKAHEAD
    assert rows[-1] == {"line": 21, "text": "brotli"}
    assert peak < len(text)


@pytest.mark.parametrize(
    ("name", "text", "expected"),
    [
        (
            "setup.py",
            (
                'from setuptools import setup\nrequirements = ["brotlicffi"]\n'
                'setup(description="Brotli benchmark", install_requires=requirements)'
            ),
            ["brotlicffi"],
        ),
        (
            "setup.cfg",
            (
                "[metadata]\ndescription = Brotli benchmark\n[options]\n"
                "install_requires =\n  brotli>=1.2.1\n"
            ),
            ["brotli>=1.2.1"],
        ),
        (
            "pipfile",
            '[scripts]\nbenchmark = "brotli --help"\n[packages]\nbrotli = "*"\n',
            ['"*"'],
        ),
        (
            "pipfile.lock",
            (
                '{"_meta":{"description":"Brotli benchmark"},'
                '"default":{"brotlicffi":{"version":"==1.2.1.0"}}}'
            ),
            ['{"version": "==1.2.1.0"}'],
        ),
        (
            "app.csproj",
            (
                "<Project><PropertyGroup><Description>Brotli benchmark</Description>"
                '</PropertyGroup><ItemGroup><PackageReference Include="BrotliSharpLib" '
                'Version="0.3.3" /></ItemGroup></Project>'
            ),
            ["BrotliSharpLib"],
        ),
        (
            "Directory.Packages.props",
            (
                '<Project xmlns="urn:test"><ItemGroup>'
                '<PackageVersion Include="BrotliSharpLib" Version="0.3.3" />'
                "</ItemGroup></Project>"
            ),
            ["BrotliSharpLib"],
        ),
        (
            "app.nuspec",
            (
                '<package><metadata><dependencies><dependency id="BrotliSharpLib" />'
                "</dependencies></metadata></package>"
            ),
            ["BrotliSharpLib"],
        ),
        (
            "packages.config",
            '<packages><package id="BrotliSharpLib" version="0.3.3" /></packages>',
            ["BrotliSharpLib"],
        ),
        (
            "packages.lock.json",
            '{"dependencies":{"net9.0":{"BrotliSharpLib":{"resolved":"0.3.3"}}}}',
            ["BrotliSharpLib"],
        ),
        (
            "app.deps.json",
            (
                '{"libraries":{"BrotliSharpLib/0.3.3":{}},'
                '"targets":{".NETCoreApp":{"BrotliSharpLib/0.3.3":{}}}}'
            ),
            ["BrotliSharpLib/0.3.3", "BrotliSharpLib/0.3.3"],
        ),
    ],
)
def test_python_and_dotnet_dependencies_are_extracted_from_owned_fields(name, text, expected):
    assert [match["text"] for match in dependencies.dependency_matches(text, name)] == expected


@pytest.mark.parametrize(
    ("name", "text"),
    [
        ("setup.py", 'setup(description="Brotli benchmark", install_requires=["zlib"])'),
        ("setup.cfg", "[metadata]\ndescription = Brotli benchmark\n[options]\nzip_safe=true"),
        ("pipfile", '[scripts]\nbenchmark = "brotli --help"\n[packages]\nzlib = "*"'),
        ("pipfile.lock", '{"_meta":{"description":"Brotli benchmark"},"default":{}}'),
        ("requirements.txt", "# Install Brotli for an optional benchmark\n-r brotli.in\nzlib"),
        (
            "app.csproj",
            (
                "<Project><PropertyGroup><Description>Brotli benchmark</Description>"
                '</PropertyGroup><ItemGroup><None Include="brotli-results.txt" />'
                "</ItemGroup></Project>"
            ),
        ),
        (
            "app.nuspec",
            "<package><metadata><description>Brotli benchmark</description></metadata></package>",
        ),
        (
            "packages.lock.json",
            '{"description":"Brotli benchmark","dependencies":{"net9.0":{"zlib":{}}}}',
        ),
        (
            "app.deps.json",
            '{"description":"Brotli benchmark","libraries":{"zlib/1.0":{}}}',
        ),
    ],
)
def test_descriptions_scripts_comments_and_nonpackage_items_are_not_dependencies(name, text):
    assert dependencies.dependency_matches(text, name) == []


def test_dotnet_xml_comments_and_cdata_are_not_package_items():
    text = """<Project>
<!-- <PackageReference Include="BrotliSharpLib" /> -->
<![CDATA[<PackageReference Include="BrotliSharpLib" />]]>
<ItemGroup><PackageReference Include="zlib" /></ItemGroup>
</Project>
"""
    assert dependencies.dependency_matches(text, "app.csproj") == []


def test_requirements_support_named_extras_vcs_editable_and_direct_urls():
    text = """# Brotli prose is ignored.
httpx[brotli]>=0.28
git+https://example.invalid/project.git#egg=brotlicffi
-e git+https://example.invalid/project.git#egg=Brotli
https://example.invalid/releases/brotli-1.2.1.tar.gz
--extra-index-url https://brotli.example.invalid/simple
"""
    assert dependencies.dependency_matches(text, "requirements-dev.txt") == [
        {"line": 2, "text": "httpx[brotli]>=0.28"},
        {"line": 3, "text": "git+https://example.invalid/project.git#egg=brotlicffi"},
        {"line": 4, "text": "-e git+https://example.invalid/project.git#egg=Brotli"},
        {"line": 5, "text": "https://example.invalid/releases/brotli-1.2.1.tar.gz"},
    ]


def test_requirements_support_local_renamed_direct_and_editable_equals_sources():
    text = """./vendor/brotli
codec @ git+https://github.com/google/brotli
--editable=git+https://example.invalid/project.git#egg=brotlicffi
codec@git+https://github.com/google/brotli
vendor/brotlicffi
C:\\vendor\\brotli
../ordinary-zlib
"""
    assert dependencies.dependency_matches(text, "requirements.txt") == [
        {"line": 1, "text": "./vendor/brotli"},
        {"line": 2, "text": "codec @ git+https://github.com/google/brotli"},
        {
            "line": 3,
            "text": "--editable=git+https://example.invalid/project.git#egg=brotlicffi",
        },
        {"line": 4, "text": "codec@git+https://github.com/google/brotli"},
        {"line": 5, "text": "vendor/brotlicffi"},
        {"line": 6, "text": "C:\\vendor\\brotli"},
    ]


def test_setup_literals_do_not_follow_calls_or_extra_names_as_dependencies():
    text = """from setuptools import setup
setup(
    description="Brotli utility",
    install_requires=read_requirements("brotli-requirements.txt"),
    extras_require={"brotli": ["zlib"]},
)
"""
    assert dependencies.dependency_matches(text, "setup.py") == []


def test_setup_alias_graph_is_bounded_and_handles_annotations_without_values():
    source = 'unused: str\na0 = ["brotli"]\n'
    source += "\n".join(f"a{i} = [a{i - 1}, a{i - 1}]" for i in range(1, 1100))
    source += "\nsetup(install_requires=a1099)\n"
    assert [row["text"] for row in dependencies.dependency_matches(source, "setup.py")] == [
        "brotli"
    ]
    assert (
        dependencies.dependency_matches("a = b\nb = a\nsetup(install_requires=a)", "setup.py") == []
    )


def test_setup_literal_kwargs_and_list_concatenation_are_followed_without_execution():
    source = """from setuptools import setup
extras = ["zlib"]
requirements = ["brotli"] + extras
kwargs = {"description": "Brotli prose", "install_requires": requirements}
setup(**kwargs)
"""
    assert dependencies.dependency_matches(source, "setup.py") == [
        {"field": "install_requires", "text": "brotli", "line": 3}
    ]


def test_poetry_group_names_are_not_dependencies_without_dependency_entries():
    text = """[tool.poetry.group.brotli]
optional = true

[tool.poetry.group.runtime.dependencies]
zlib = "*"
"""
    assert dependencies.dependency_matches(text, "pyproject.toml") == []


@pytest.mark.parametrize(
    ("name", "text", "kind"),
    [
        (
            "pipfile",
            "[packages]\nzlib = " + "[" * 2_000 + "0" + "]" * 2_000,
            "Pipfile TOML",
        ),
        (
            "pipfile.lock",
            '{"default":{"zlib":' + "[" * 50_000 + "0" + "]" * 50_000 + "}}",
            "Pipfile lock JSON",
        ),
    ],
)
def test_recursive_structured_metadata_fails_closed_without_a_brotli_token(name, text, kind):
    assert dependencies.dependency_matches(text, name) == [
        {
            "text": (
                f"Incomplete {kind} dependency parsing: nesting exceeds the parser depth; "
                "selection is unresolved."
            ),
            "parse_incomplete": True,
        }
    ]


def test_deep_dotnet_dependency_graph_uses_iterative_traversal():
    payload = "{}"
    for _ in range(2_000):
        payload = '{"zlib":{"dependencies":' + payload + "}}"
    text = '{"dependencies":{"net9.0":' + payload + "}}"
    assert dependencies.dependency_matches(text, "packages.lock.json") == []


def test_each_structured_manifest_parser_retains_only_one_lookahead_row():
    count = dependencies.DEPENDENCY_MATCH_LOOKAHEAD
    cases = {
        "pyproject.toml": "[project]\ndependencies=["
        + ",".join(f'"brotli-{index}"' for index in range(100))
        + "]",
        "setup.py": "setup(install_requires=["
        + ",".join(f'"brotli-{index}"' for index in range(100))
        + "])",
        "setup.cfg": "[options]\ninstall_requires=\n"
        + "\n".join(f"  brotli-{index}" for index in range(100)),
        "pipfile": "[packages]\n" + "\n".join(f'brotli-{index}="*"' for index in range(100)),
        "pipfile.lock": '{"default":{'
        + ",".join(f'"brotli-{index}":{{"version":"*"}}' for index in range(100))
        + "}}",
        "app.csproj": "<Project>"
        + "".join(f'<PackageReference Include="brotli-{index}" />' for index in range(100))
        + "</Project>",
        "packages.lock.json": '{"dependencies":{"net9.0":{'
        + ",".join(f'"brotli-{index}":{{}}' for index in range(100))
        + "}}}",
    }
    for name, text in cases.items():
        assert len(dependencies.dependency_matches(text, name)) == count
