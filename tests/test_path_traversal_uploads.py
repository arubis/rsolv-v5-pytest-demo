"""RED test: path traversal in read_upload (CWE-22).

The secure property: read_upload() must never return content of a file that
lives outside the uploads/ directory, regardless of what the caller supplies
as a filename.  Supplying a path such as "../sensitive.txt" should be rejected
(raise an exception) rather than silently opening a file outside the sandbox.
"""

import pytest
from app.uploads import read_upload


def test_path_traversal_cannot_escape_uploads_directory(tmp_path, monkeypatch):
    """read_upload must reject filenames that traverse outside uploads/.

    Secure behaviour: an exception is raised when a '../' traversal is attempted.
    On vulnerable code this test FAILS because the function happily opens the
    file outside the sandbox without raising any exception.
    """
    # Build a fake uploads sandbox
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir()
    (uploads_dir / "safe.txt").write_text("safe content\n")

    # Place a "sensitive" file one level above uploads/ — outside the sandbox
    sensitive = tmp_path / "sensitive.txt"
    sensitive.write_text("top secret\n")

    # Relocate the working directory so "uploads/" resolves to our sandbox
    monkeypatch.chdir(tmp_path)

    # SECURE behaviour: a traversal filename must be rejected with an exception.
    # On vulnerable code this assertion FAILS because no exception is raised and
    # the sensitive file outside uploads/ is returned successfully.
    with pytest.raises(Exception):
        read_upload("../sensitive.txt")


def test_path_traversal_does_not_leak_out_of_sandbox_content(tmp_path, monkeypatch):
    """read_upload must not return content from files outside uploads/.

    Secure behaviour: calling read_upload with a traversal path either raises
    or returns something other than the sensitive file's content.
    On vulnerable code this test FAILS because the out-of-sandbox content is
    returned unchanged.
    """
    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir()

    sensitive = tmp_path / "sensitive.txt"
    sensitive.write_text("top secret\n")

    monkeypatch.chdir(tmp_path)

    # Attempt path traversal — capture the result, if any
    result = None
    raised = False
    try:
        result = read_upload("../sensitive.txt")
    except Exception:
        raised = True

    if raised:
        # Any exception is the secure outcome — traversal was blocked
        return

    # If no exception was raised the function returned something — it must NOT
    # be the sensitive content that lives outside the uploads/ directory.
    assert result != "top secret\n", (
        "Path traversal succeeded: read_upload returned content from a file "
        "outside the uploads/ directory ('top secret\\n')"
    )
