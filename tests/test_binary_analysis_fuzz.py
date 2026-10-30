import fcntl
import hashlib
import json
import resource
import sys
from pathlib import Path
from typing import Any

import fuzz_binary_analysis as subject
import fuzz_with_atheris as atheris_adapter
import pytest
import run_atheris_campaign as campaign
import run_fuzz_corpus as runner


def test_structured_seed_corpus_reaches_every_native_target():
    seeds = subject.seed_corpus()
    observed: dict[str, Any] = {}
    for name, data in seeds.items():
        observed[name] = subject.exercise_one(data)

    assert observed["layout-pe"]["kind"] == "pe"
    assert observed["layout-mach-o"]["kind"] == "mach_o"
    assert observed["layout-wasm"]["kind"] == "wasm"
    assert observed["payload-ar"][0] == "ar"
    assert observed["payload-ar"][1][0][0] == "seed.bin"
    assert observed["oci-docker-save"][0][1] == (("app/decoder", 4),)
    assert observed["graph-aarch64"]["machine"] == subject.EM_AARCH64
    assert observed["debug-elf"]["identity"]["format"] == "elf"
    assert observed["debug-pair"]["status"] == "verified"


@pytest.mark.parametrize("selector", range(len(subject.FUZZ_TARGETS)))
def test_native_fuzz_targets_reject_arbitrary_bytes_without_side_effects(selector):
    subject.fuzz_one(bytes((selector,)) + bytes(range(256)))


def test_native_fuzz_entry_hides_only_expected_malformed_input(monkeypatch):
    monkeypatch.setattr(
        subject,
        "FUZZ_TARGETS",
        (subject.FuzzTarget("broken", lambda _data: 1 / 0), *subject.FUZZ_TARGETS[1:]),
    )
    with pytest.raises(ZeroDivisionError):
        subject.fuzz_one(b"\0payload")
    monkeypatch.setattr(
        subject,
        "FUZZ_TARGETS",
        (
            subject.FuzzTarget(
                "malformed",
                lambda _data: (_ for _ in ()).throw(ValueError("malformed")),
                (ValueError,),
            ),
            *subject.FUZZ_TARGETS[1:],
        ),
    )
    subject.fuzz_one(b"\0payload")


def test_seed_writer_is_deterministic_and_refuses_existing_output(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    assert subject.main(["--write-seeds", str(first)]) == 0
    assert subject.main(["--write-seeds", str(second)]) == 0
    first_manifest = json.loads((first / "manifest.json").read_text())
    second_manifest = json.loads((second / "manifest.json").read_text())
    assert first_manifest == second_manifest
    for row in first_manifest["seeds"]:
        data = (first / row["name"]).read_bytes()
        assert len(data) == row["size"]
        assert hashlib.sha256(data).hexdigest() == row["sha256"]
        assert data == (second / row["name"]).read_bytes()
    with pytest.raises(FileExistsError):
        subject.main(["--write-seeds", str(first)])


@pytest.mark.skipif(runner.find_timeout() is None, reason="GNU timeout is required")
def test_bounded_runner_executes_one_input_and_binds_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.tempfile, "gettempdir", lambda: str(tmp_path))
    corpus = tmp_path / "input"
    corpus.write_bytes(subject.seed_corpus()["layout-wasm"])
    output = tmp_path / "result"

    assert runner.main(["binary", str(output), str(corpus), "--memory-bytes", str(512 << 20)]) == 0

    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["workers"] == 1
    assert manifest["memory_bytes_per_process"] == 512 << 20
    assert manifest["results"][0]["status"] == "complete"
    assert manifest["results"][0]["returncode"] == 0
    assert manifest["results"][0]["input_sha256"] == hashlib.sha256(corpus.read_bytes()).hexdigest()
    assert (output / manifest["results"][0]["log"]).read_text() == ""


def test_runner_rejects_symlinks_and_existing_output(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(runner, "find_timeout", lambda: "/usr/bin/timeout")
    target = tmp_path / "target"
    target.write_bytes(b"seed")
    link = tmp_path / "link"
    link.symlink_to(target)
    with pytest.raises(SystemExit):
        runner.main(["binary", str(tmp_path / "out"), str(link)])
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(SystemExit):
        runner.main(["binary", str(existing), str(target)])


def test_runner_lock_serializes_jobs_without_creating_output(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(runner, "find_timeout", lambda: "/usr/bin/timeout")
    corpus = tmp_path / "input"
    corpus.write_bytes(b"seed")
    output = tmp_path / "output"
    with (tmp_path / "brotli-checker-fuzz-corpus.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(SystemExit):
            runner.main(["binary", str(output), str(corpus)])
    assert not output.exists()


def test_input_is_staged_with_stable_content_and_digest(tmp_path):
    source, staged = tmp_path / "source", tmp_path / "staged"
    source.write_bytes(b"immutable corpus input")
    size, digest = runner._stage_input(source, staged, 1024)  # noqa: SLF001
    assert size == len(source.read_bytes())
    assert digest == hashlib.sha256(source.read_bytes()).hexdigest()
    assert staged.read_bytes() == source.read_bytes()


def test_runner_records_timeout_without_treating_it_as_completion(tmp_path, monkeypatch):
    monkeypatch.setattr(runner.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(runner, "find_timeout", lambda: "/usr/bin/timeout")
    corpus = tmp_path / "input"
    corpus.write_bytes(b"seed")
    monkeypatch.setattr(runner, "_run_one", lambda _spec: (124, 1.0, 100))

    output = tmp_path / "timeout"
    assert runner.main(["binary", str(output), str(corpus)]) == 1
    result = json.loads((output / "manifest.json").read_text())["results"][0]
    assert result["status"] == "time_limit"
    assert result["returncode"] == 124


@pytest.mark.skipif(runner.find_timeout() is None, reason="GNU timeout is required")
def test_subprocess_supervisor_applies_memory_limit_and_dedicated_tmp(tmp_path):
    harness = tmp_path / "probe.py"
    harness.write_text(
        "import json, os, resource\n"
        "print(json.dumps({'limit': resource.getrlimit(resource.RLIMIT_AS)[0], "
        "'tmp': os.environ['TMPDIR']}))\n"
    )
    source = tmp_path / "input"
    source.write_bytes(b"seed")
    temporary = tmp_path / "temporary"
    temporary.mkdir()
    log = tmp_path / "probe.log"
    memory = 384 << 20
    with (tmp_path / "lock").open("a+") as lock:
        code, _, _ = runner._run_one(  # noqa: SLF001
            runner.RunSpec(
                harness=harness,
                guard=Path(runner.__file__),
                working_directory=runner.ROOT,
                source=source,
                log=log,
                temporary=temporary,
                timeout=Path(runner.find_timeout() or ""),
                timeout_seconds=5,
                memory_bytes=memory,
                lock_descriptor=lock.fileno(),
            )
        )

    assert code == 0
    observation = json.loads(log.read_text())
    assert observation == {"limit": memory, "tmp": str(temporary)}
    assert resource.getrlimit(resource.RLIMIT_AS)[0] != memory


def test_runner_resource_limits_must_be_positive(tmp_path):
    corpus = tmp_path / "input"
    corpus.write_bytes(b"seed")
    for option in ("--memory-bytes", "--timeout-seconds", "--max-input-bytes"):
        with pytest.raises(SystemExit):
            runner.main(["binary", str(tmp_path / option[2:]), str(corpus), option, "0"])


def test_runner_fails_closed_when_gnu_timeout_is_unavailable(tmp_path, monkeypatch):
    corpus = tmp_path / "input"
    corpus.write_bytes(b"seed")
    output = tmp_path / "output"
    monkeypatch.setattr(runner, "find_timeout", lambda: None)
    with pytest.raises(SystemExit):
        runner.main(["binary", str(output), str(corpus)])
    assert not output.exists()


def test_atheris_adapter_binds_pinned_backend_and_selected_harness(monkeypatch):
    events = []

    class InstrumentImports:
        def __enter__(self):
            events.append("instrument")

        def __exit__(self, *_args):
            return False

    class FakeAtheris:
        @staticmethod
        def instrument_imports(*, include):
            assert include == atheris_adapter.INSTRUMENTED_MODULES["binary"]
            return InstrumentImports()

        @staticmethod
        def Setup(arguments, callback):  # noqa: N802 -- Mirrors the optional backend API.
            events.append((arguments, callback))

        @staticmethod
        def Fuzz():  # noqa: N802 -- Mirrors the optional backend API.
            events.append("fuzz")

    monkeypatch.setattr(atheris_adapter, "_load_atheris", FakeAtheris)
    assert atheris_adapter.main(["binary", "corpus", "-atheris_runs=10"]) == 0
    assert events == [
        "instrument",
        ([sys.argv[0], "corpus", "-atheris_runs=10"], subject.fuzz_one),
        "fuzz",
    ]


def test_atheris_adapter_rejects_missing_wrong_or_unknown_backend(monkeypatch, capsys):
    assert atheris_adapter.main([]) == 2
    assert "usage:" in capsys.readouterr().err
    monkeypatch.setattr(atheris_adapter.importlib, "import_module", lambda _name: object())
    monkeypatch.setattr(atheris_adapter.importlib.metadata, "version", lambda _name: "0.0")
    with pytest.raises(RuntimeError, match=r"required; found 0\.0"):
        atheris_adapter._load_atheris()  # noqa: SLF001


def test_atheris_metrics_parse_final_coverage_line():
    observed = campaign._metrics(  # noqa: SLF001
        b"#10 pulse cov: 4 ft: 5 corp: 2/10b\n"
        b"#100 DONE cov: 12 ft: 34 corp: 8/2Kb lim: 4096 exec/s: 100\n"
    )
    assert observed == {
        "executions": 100,
        "coverage": 12,
        "features": 34,
        "corpus_files": 8,
        "corpus_bytes": 2048,
    }
    assert campaign._metrics(b"no coverage metrics") is None  # noqa: SLF001


def test_bounded_atheris_campaign_binds_seeds_sources_and_metrics(tmp_path, monkeypatch):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    (seeds / "seed").write_bytes(subject.seed_corpus()["layout-wasm"])
    snapshot = tmp_path / "snapshot"
    (snapshot / "scripts").mkdir(parents=True)
    harness = snapshot / "scripts/fuzz_with_atheris.py"
    guard = snapshot / "scripts/run_fuzz_corpus.py"
    harness.write_text("# harness\n")
    guard.write_text("# guard\n")
    source = runner.SourceSnapshot(snapshot, harness, guard, "a" * 64)
    monkeypatch.setattr(campaign.importlib.metadata, "version", lambda _name: "3.1.0")
    monkeypatch.setattr(campaign, "_snapshot_sources", lambda _harness: source)
    monkeypatch.setattr(campaign.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(campaign, "find_timeout", lambda: "/usr/bin/timeout")

    def run(spec):
        corpus = Path(spec.command[3])
        (corpus / "new").write_bytes(b"interesting")
        spec.log.write_bytes(b"#100 DONE cov: 12 ft: 34 corp: 2/20b lim: 4096 exec/s: 100\n")
        return 0, 0.5, 1234

    monkeypatch.setattr(campaign, "_run_supervised", run)
    output = tmp_path / "output"
    assert campaign.main(["binary", str(seeds), str(output), "--runs", "100"]) == 0
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["status"] == "complete"
    assert manifest["atheris_version"] == "3.1.0"
    assert manifest["tool_versions"]["atheris"] == "3.1.0"
    assert manifest["source_snapshot_sha256"] == "a" * 64
    assert manifest["workers"] == 1
    assert manifest["metrics"]["coverage"] == 12
    assert {row["name"] for row in manifest["retained_corpus"]} == {"0000", "new"}


def test_atheris_campaign_rejects_symlink_seed(tmp_path, monkeypatch):
    seeds = tmp_path / "seeds"
    seeds.mkdir()
    target = seeds / "target"
    target.write_bytes(b"seed")
    (seeds / "link").symlink_to(target)
    monkeypatch.setattr(campaign.importlib.metadata, "version", lambda _name: "3.1.0")
    monkeypatch.setattr(campaign.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setattr(campaign, "find_timeout", lambda: "/usr/bin/timeout")
    with pytest.raises(SystemExit):
        campaign.main(["binary", str(seeds), str(tmp_path / "output")])


def test_atheris_completed_count_is_not_last_corpus_update():
    log = b"#9931 REDUCE cov: 595 ft: 912 corp: 94/57Kb\nDone 10000 in 0 second(s)\n"
    observed = campaign._metrics(log)  # noqa: SLF001
    assert observed is not None
    assert observed["executions"] == 10000
    assert observed["coverage"] == 595
