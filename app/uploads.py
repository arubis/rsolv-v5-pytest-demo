"""Reads uploaded files. The filename is validated to stay within the
uploads directory, preventing directory traversal (CWE-22).
"""

import os


def read_upload(filename):
    uploads_dir = os.path.realpath("uploads")
    requested_path = os.path.realpath(os.path.join("uploads", filename))
    if not requested_path.startswith(uploads_dir + os.sep) and requested_path != uploads_dir:
        raise ValueError(f"Access denied: path outside uploads directory: {filename!r}")
    with open(requested_path) as handle:
        return handle.read()
