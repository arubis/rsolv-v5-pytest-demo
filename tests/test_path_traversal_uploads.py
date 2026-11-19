"""
RED test for CWE-22: Path Traversal in app/uploads.py

Security property: read_upload() must reject any filename that contains path
traversal sequences before attempting to access the filesystem.  Supplying
"../secret.txt" should raise ValueError — not silently serve a file that
lives outside the uploads/ directory.
"""

import os
import pytest


TRAVERSAL_PAYLOADS = [
    "../etc/passwd",
    "../../etc/shadow",
    "../secret.txt",
    "subdir/../../outside.txt",
]


@pytest.mark.parametrize("payload", TRAVERSAL_PAYLOADS)
def test_read_upload_raises_on_traversal_payload(tmp_path, monkeypatch, payload):
    """
    Secure behavior: read_upload() must raise ValueError when the caller
    supplies a filename that escapes the uploads/ directory via '..'.

    RED (vulnerable code): no validation exists; the function attempts to
    resolve the path rather than raise, so pytest.raises(ValueError) is NOT
    satisfied and the test FAILS.

    GREEN (fixed code): read_upload() detects the traversal and raises
    ValueError before touching the filesystem.
    """
    from app.uploads import read_upload

    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir()
    # Place a legitimate file so normal usage still works
    (uploads_dir / "public.txt").write_text("public content")

    # Change working directory so the relative "uploads/…" path resolves inside tmp_path
    monkeypatch.chdir(tmp_path)

    with pytest.raises(ValueError):
        read_upload(payload)


def test_legitimate_filename_still_works(tmp_path, monkeypatch):
    """
    Sanity check: a plain filename (no traversal) must continue to work after
    the fix is applied.  This ensures the fix does not over-block.
    """
    from app.uploads import read_upload

    uploads_dir = tmp_path / "uploads"
    uploads_dir.mkdir()
    (uploads_dir / "hello.txt").write_text("hello\n")

    monkeypatch.chdir(tmp_path)

    content = read_upload("hello.txt")
    assert content == "hello\n"
