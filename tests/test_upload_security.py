import pytest
from app.uploads import read_upload


def test_upload_filename_validation():
    evil = chr(46) + chr(46) + chr(47) + "out.txt"
    with pytest.raises(ValueError):
        read_upload(evil)
