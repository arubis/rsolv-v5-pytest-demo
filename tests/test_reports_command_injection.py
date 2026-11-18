"""RED test: command injection in app/reports.py line_count() (CWE-78).

The vulnerability: subprocess.run(f"wc -l < {filename}", shell=True, ...)
interpolates `filename` directly into a shell command, so an attacker who
controls the filename string can inject arbitrary shell commands.

The security property that SHOULD hold: passing a filename that contains
shell metacharacters must NOT cause arbitrary commands to be executed.
"""

import os
import pytest
from app.reports import line_count


def test_line_count_does_not_execute_injected_shell_commands(tmp_path):
    """An attacker-controlled filename with shell metacharacters must not
    result in arbitrary command execution.

    On the VULNERABLE code this test FAILS because the injected command
    runs and creates the sentinel file.  After the fix (no shell=True /
    proper escaping) the injection is neutralised and the file is never
    created, so the assertion PASSES.
    """
    sentinel = tmp_path / "injected_sentinel.txt"

    # Craft a filename that, when interpolated into  "wc -l < {filename}",
    # causes the shell to also run:  touch <sentinel>
    # The real file part is /dev/null so wc -l has something to read.
    malicious_filename = f"/dev/null; touch {sentinel}"

    # Call the function with the injection payload.
    # We deliberately ignore the return value – we care only about whether
    # the side-effect (sentinel file creation) occurred.
    try:
        line_count(malicious_filename)
    except Exception:
        # Even if line_count raises, the injection may already have fired;
        # the sentinel check below is the authoritative verdict.
        pass

    # Security invariant: the injected command must NOT have executed.
    assert not sentinel.exists(), (
        "Command injection succeeded: the shell executed the injected "
        f"'touch {sentinel}' command embedded in the filename.  "
        "line_count() must not pass unsanitised filenames to a shell."
    )
