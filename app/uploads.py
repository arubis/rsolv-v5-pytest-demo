"""Reads uploaded files. The name is validated to prevent directory traversal
(CWE-22): the resolved path must remain inside the uploads/ directory."""

import os


def read_upload(filename):
    uploads_dir = os.path.realpath("uploads")
    target = os.path.realpath(os.path.join("uploads", filename))
    if not target.startswith(uploads_dir + os.sep) and target != uploads_dir:
        raise ValueError(f"Invalid filename: path traversal detected: {filename!r}")
    with open(target) as handle:
        return handle.read()
