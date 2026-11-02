import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def probe(folder, report, *, explicit=None, debug_root=None):
    environment = dict(os.environ)
    for key in ("PYTEST_ADDOPTS", "PYTEST_PLUGINS", "PYTEST_DEBUG_TEMPROOT"):
        environment.pop(key, None)
    environment.update(PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PROBE_REPORT=str(report))
    if debug_root is not None:
        environment["PYTEST_DEBUG_TEMPROOT"] = str(debug_root)
    command = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-c", "pytest.ini"]
    if explicit is not None:
        command.extend(("--basetemp", str(explicit)))
    completed = subprocess.run(  # noqa: S603 -- Fixed local pytest and authored probe.
        command,
        check=False,
        cwd=folder,
        env=environment,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    return json.loads(report.read_text())


@pytest.mark.parametrize("mode", ["owned", "explicit", "environment"])
def test_each_pytest_process_owns_its_default_root_without_forwarded_flags(tmp_path, mode):
    folder = tmp_path / "probe"
    folder.mkdir()
    shutil.copyfile(ROOT / "conftest.py", folder / "conftest.py")
    (folder / "pytest.ini").write_text("[pytest]\nfilterwarnings = error\n")
    (folder / "test_probe.py").write_text(
        "import json, os\nfrom pathlib import Path\n"
        "def test_root(tmp_path, tmp_path_factory, request):\n"
        "    root = tmp_path_factory.getbasetemp()\n"
        "    assert tmp_path.is_relative_to(root)\n"
        "    Path(os.environ['PROBE_REPORT']).write_text(json.dumps({\n"
        "        'root': str(root), 'args': list(request.config.invocation_params.args),\n"
        "        'environment': {key: os.environ.get(key) for key in \n"
        "            ('PYTEST_ADDOPTS', 'PYTEST_DEBUG_TEMPROOT')}\n"
        "    }))\n"
    )
    roots = []
    debug_root = tmp_path / "environment-root" if mode == "environment" else None
    if debug_root is not None:
        debug_root.mkdir()
    for index in range(2):
        requested = tmp_path / f"retained-{index}" if mode == "explicit" else None
        result = probe(
            folder, tmp_path / f"report-{index}.json", explicit=requested, debug_root=debug_root
        )
        actual = Path(result["root"])
        roots.append(actual)
        assert result["environment"] == {
            "PYTEST_ADDOPTS": None,
            "PYTEST_DEBUG_TEMPROOT": str(debug_root) if debug_root is not None else None,
        }
        if debug_root is not None:
            assert actual.parent == debug_root
        if mode == "explicit":
            assert actual == requested
            assert actual.is_dir()
        else:
            assert "--basetemp" not in result["args"]
            assert not actual.exists()
    assert roots[0] != roots[1]
