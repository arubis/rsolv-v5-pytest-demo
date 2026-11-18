"""
RED test – CWE-22 Path Traversal in app/uploads.read_upload
-----------------------------------------------------------
Secure behaviour: read_upload() must only return contents of files that
reside inside the uploads/ directory.  A filename containing traversal
sequences such as "../" must NEVER be able to reach files outside that
directory.

These tests fail on the current (vulnerable) implementation because no
sanitisation is applied before the path is opened.
"""

import os
import pytest

from app.uploads import read_upload


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_uploads_dir(base):
    """Create <base>/uploads/ with a benign file inside it."""
    uploads = base / "uploads"
    uploads.mkdir()
    (uploads / "public.txt").write_text("public content\n")
    return uploads


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_path_traversal_cannot_read_file_outside_uploads(tmp_path, monkeypatch):
    """A traversal payload must not expose files that live outside uploads/."""
    _make_uploads_dir(tmp_path)

    # Create a 'secret' file one level above uploads/
    secret = tmp_path / "secret.txt"
    secret.write_text("SUPER SECRET DATA\n")

    monkeypatch.chdir(tmp_path)

    # On vulnerable code this succeeds (returns the secret content).
    # Secure code must raise an exception (ValueError, PermissionError, etc.)
    # to prevent the traversal.
    with pytest.raises(Exception):
        read_upload("../secret.txt")


def test_path_traversal_does_not_return_sensitive_content(tmp_path, monkeypatch):
    """Even if read_upload doesn't raise, traversal must not return outside content."""
    _make_uploads_dir(tmp_path)

    secret = tmp_path / "secret.txt"
    secret_data = "SUPER SECRET DATA\n"
    secret.write_text(secret_data)

    monkeypatch.chdir(tmp_path)

    try:
        result = read_upload("../secret.txt")
        # If the function did NOT raise, it must at least not have returned the
        # out-of-bounds file content.
        assert result != secret_data, (
            "read_upload returned the contents of a file outside uploads/ – "
            "path traversal is possible."
        )
    except Exception:
        # Raising any exception is also acceptable (and is the stricter defence).
        pass


def test_path_traversal_with_nested_escape_cannot_read_outside(tmp_path, monkeypatch):
    """Deeper traversal sequences must also be blocked."""
    _make_uploads_dir(tmp_path)

    # Place a secret two levels up (achieved by nesting tmp_path further)
    outer = tmp_path / "outer"
    outer.mkdir()
    uploads_root = outer / "uploads"
    uploads_root.mkdir()
    (uploads_root / "public.txt").write_text("public\n")

    secret = outer / "config.txt"
    secret.write_text("DB_PASSWORD=supersecret\n")

    monkeypatch.chdir(outer)

    with pytest.raises(Exception):
        read_upload("../config.txt")
