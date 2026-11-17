from app.calc import calculate
from app.passwords import check_password, hash_password
from app.reports import line_count
from app.sessions import dump_session, load_session
from app.uploads import read_upload


def test_calculate_adds_numbers():
    assert calculate("2 + 3") == 5


def test_a_password_checks_against_its_own_hash():
    assert check_password("s3cret", hash_password("s3cret"))


def test_line_count_counts_lines(tmp_path):
    report = tmp_path / "report.txt"
    report.write_text("a\nb\nc\n")

    assert line_count(str(report)) == 3


def test_a_session_round_trips():
    assert load_session(dump_session({"user": "alice"})) == {"user": "alice"}


def test_read_upload_reads_a_file_in_uploads():
    assert read_upload("greeting.txt") == "hello\n"
