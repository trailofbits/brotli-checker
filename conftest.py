"""Own pytest temporary roots per process, without inherited CLI/environment flags."""

import os
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest


@pytest.hookimpl(tryfirst=True)
def pytest_configure(config: pytest.Config) -> None:
    if config.option.basetemp is not None:
        return
    temporary = TemporaryDirectory(prefix="case-", dir=os.environ.get("PYTEST_DEBUG_TEMPROOT"))
    config.add_cleanup(temporary.cleanup)
    config.option.basetemp = Path(temporary.name)
