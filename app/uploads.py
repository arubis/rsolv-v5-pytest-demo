"""Reads uploaded files. Deliberately vulnerable: the name is concatenated
into the path, so "../" escapes the uploads directory (CWE-22)."""

import os


def read_upload(filename):
    uploads_dir = os.path.realpath("uploads")
    target = os.path.realpath(os.path.join("uploads", filename))
    if not target.startswith(uploads_dir + os.sep) and target != uploads_dir:
        raise ValueError(f"Invalid filename: path traversal detected in {filename!r}")
    with open(target) as handle:
        return handle.read()
