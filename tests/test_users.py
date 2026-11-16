from app.users import add_user, connect, find_user


def test_find_user_returns_the_named_user():
    conn = connect()
    add_user(conn, "alice", "alice@example.com")

    assert find_user(conn, "alice")[1:] == ("alice", "alice@example.com")


def test_find_user_returns_none_for_an_unknown_name():
    conn = connect()

    assert find_user(conn, "nobody") is None
