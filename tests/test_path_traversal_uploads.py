"""RED test: path traversal vulnerability in app/uploads.py (CWE-22).

Secure property: read_upload() must never read files outside the uploads/
directory, regardless of what filename string the caller provides.

On the current vulnerable code these tests FAIL because the filename is
concatenated straight into the path with no canonicalization check.
"""

import os
import pytest

from app.uploads import read_upload


def test_path_traversal_cannot_reach_outside_uploads(tmp_path):
    """A traversal payload must not allow reading files outside uploads/.

    We create a sentinel file in a temporary directory (outside uploads/)
    and compute the relative traversal path needed to reach it from inside
    uploads/.  Secure behavior requires an exception to be raised before
    the file is opened.

    RED: on vulnerable code read_upload() opens the sentinel file without
    complaint, so pytest.raises fails with 'DID NOT RAISE'.
    """
    sentinel = tmp_path / "sentinel.txt"
    sentinel.write_text("TOP SECRET")

    uploads_abs = os.path.abspath("uploads")
    # Build the '../' sequence that leads from uploads/ to the sentinel file
    traversal = os.path.relpath(str(sentinel), uploads_abs)
    # traversal will look like "../../tmp/.../sentinel.txt"

    with pytest.raises(Exception):
        read_upload(traversal)


def test_read_upload_result_cannot_contain_outside_file_contents(tmp_path):
    """Content of a file outside uploads/ must never be returned.

    Even if no exception is raised by the fix, the returned value must
    not be the contents of the file we placed outside the uploads tree.

    RED: on vulnerable code read_upload() returns "TOP SECRET" and the
    assertion fires.
    """
    sentinel = tmp_path / "sentinel2.txt"
    sentinel.write_text("TOP SECRET CONTENT")

    uploads_abs = os.path.abspath("uploads")
    traversal = os.path.relpath(str(sentinel), uploads_abs)

    try:
        result = read_upload(traversal)
    except Exception:
        # Raising an exception is the preferred secure behaviour; test passes.
        return

    assert result != "TOP SECRET CONTENT", (
        "Path traversal succeeded: read_upload() returned the contents of a "
        "file located outside the uploads/ directory."
    )
