"""
tests/conftest.py

Sandbox/CI compatibility shim only -- NOT a change to the project's
runtime requirements.

ARCHITECTURE.md constraint C3 fixes Python 3.11 as the minimum runtime
specifically because `tomllib` (adam/common/config.py) is stdlib-only
starting in 3.11 -- see that file's own docstring and import. Some
environments this test suite runs in (e.g. this project's sandboxed dev
environment) only provide Python 3.10, which lacks `tomllib` outright and
would otherwise fail to even collect any test that imports
adam.common.config (a transitive import of most of the codebase).

`tomli` is the pure-Python backport with an API-identical surface to
`tomllib` (it's what `tomllib` itself is vendored from). When running
under Python < 3.11, this registers `tomli` under the `tomllib` name in
sys.modules *before* any test module imports adam.common.config, so
`import tomllib` resolves successfully without touching a single line of
production code. Under Python >= 3.11 this is a no-op -- the real
stdlib tomllib is used, exactly as it will be in actual deployment.
"""

from __future__ import annotations

import sys

if sys.version_info < (3, 11):
    import tomli

    sys.modules.setdefault("tomllib", tomli)
