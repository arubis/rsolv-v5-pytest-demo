"""Reads uploaded files. Deliberately vulnerable: the name is concatenated
into the path, so "../" escapes the uploads directory (CWE-22)."""

import os


def read_upload(filename):
    uploads_dir = os.path.abspath("uploads")
    requested_path = os.path.abspath(os.path.join(uploads_dir, filename))
    if not requested_path.startswith(uploads_dir + os.sep):
        raise ValueError("Access denied: path traversal detected")
    with open(requested_path) as handle:
        return handle.read()
