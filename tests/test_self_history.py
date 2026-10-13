"""The project's own history is scanned by the project's own tool (CLAUDE.md section 4, section 7):
no commit may have contained a string that a built-in rule matches. Slow, because it walks every
commit of this repository; CI checks out with full history."""

from __future__ import annotations

import pytest

from secret_scanner.app.scan_git import GitScanRequest, run_scan_git
from secret_scanner.core.errors import ExitCode
from tests.helpers import PROJECT_ROOT, FakeClock

pytestmark = [pytest.mark.requires_git, pytest.mark.slow, pytest.mark.reads_repository]


def test_the_repository_history_holds_no_secret_shaped_string() -> None:
    # default confidence: what the hygiene tests mean by "a string a built-in rule matches"
    request = GitScanRequest(path=str(PROJECT_ROOT), allow_shallow=True)
    outcome = run_scan_git(request, FakeClock())
    report = outcome.report
    if report.history_complete is False and report.stats.commits < 2:
        pytest.skip("the checkout has too little history to say anything")
    shown = [
        f"{f.rule_id} {f.location.path}@{(f.location.commit or '')[:12]}" for f in report.findings
    ]
    assert shown == []
    assert outcome.exit_code == ExitCode.OK
    assert report.stats.commits >= 1
