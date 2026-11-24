"""Reads uploaded files. Filenames are validated to prevent path traversal
(CWE-22) by resolving the canonical path and ensuring it stays within the
uploads directory.
"""

import os


def read_upload(filename):
    uploads_dir = os.path.realpath("uploads")
    target = os.path.realpath(os.path.join(uploads_dir, filename))
    if not target.startswith(uploads_dir + os.sep) and target != uploads_dir:
        raise ValueError("Invalid filename: path traversal detected")
    with open(target) as handle:
        return handle.read()
