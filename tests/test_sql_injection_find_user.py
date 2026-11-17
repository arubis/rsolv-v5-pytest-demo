"""RED test: SQL injection vulnerability in find_user (CWE-89, Issue #7).

find_user builds its WHERE clause with an f-string, so attacker-controlled
input can escape the string literal and modify the query.

Secure property asserted: a username that does not exist in the database
should NEVER cause find_user to return a row, regardless of what SQL
metacharacters appear in that username.  Any result for a non-existent name
means unsanitised input reached the database engine.
"""
from app.users import add_user, connect, find_user


def test_sql_injection_does_not_return_data_for_nonexistent_user():
    """An injection payload is not a real username; find_user must return None.

    The injection `' OR '1'='1` transforms the vulnerable query into:

        SELECT id, name, email FROM users
        WHERE name = '' OR '1'='1'

    which matches every row.  With parameterised queries the literal string
    (including the quotes and OR clause) is compared as a name, matches
    nothing, and None is returned.
    """
    conn = connect()
    add_user(conn, "alice", "alice@example.com")
    add_user(conn, "bob", "bob@example.com")

    injection_payload = "' OR '1'='1"

    # No user has this string as their actual name, so the result MUST be None.
    result = find_user(conn, injection_payload)

    assert result is None, (
        f"SQL injection succeeded: find_user returned {result!r} for a "
        f"non-existent username containing SQL metacharacters. "
        f"This proves the query is not parameterised."
    )


def test_sql_injection_does_not_bypass_admin_check():
    """An injection payload must not expose rows the caller isn't allowed to see.

    The crafted name `' OR is_admin=1 --` transforms the vulnerable query into:

        SELECT id, name, email FROM users WHERE name = '' OR is_admin=1 --'

    which silently returns the admin account.  Parameterised queries compare
    that whole string as a literal name, find nothing, and return None.
    """
    conn = connect()
    add_user(conn, "regular_user", "user@example.com", is_admin=False)
    add_user(conn, "admin_alice", "admin@example.com", is_admin=True)

    injection_payload = "' OR is_admin=1 --"

    result = find_user(conn, injection_payload)

    assert result is None, (
        f"SQL injection succeeded: find_user returned {result!r} (the admin "
        f"row) for a non-existent username containing a SQL injection payload. "
        f"This proves unsanitised input reached the query."
    )
