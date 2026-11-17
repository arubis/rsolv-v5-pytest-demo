"""RED test: proves that load_session() unsafely deserializes attacker-controlled
cookies using pickle, enabling arbitrary code execution (CWE-502).

The secure behavior that SHOULD be present — but is NOT — is that
load_session() does NOT pass raw attacker-controlled bytes into pickle.loads().
A safe implementation would use json.loads (or another safe deserializer) so
that embedded executable code can never run.
"""
import base64
import pickle
import pytest
from unittest.mock import patch, call

from app.sessions import load_session, dump_session


@pytest.fixture
def pickle_cookie():
    """A base64-encoded pickle payload simulating an untrusted session cookie."""
    payload = pickle.dumps({"user": "attacker", "role": "admin"})
    return base64.b64encode(payload).decode()


def test_load_session_does_not_invoke_pickle_loads_on_untrusted_input(pickle_cookie):
    """RED: load_session() MUST NOT pass untrusted cookie bytes to pickle.loads().

    A secure implementation would use a safe deserializer (e.g. json.loads)
    instead of pickle.loads, so that attacker-crafted payloads cannot execute
    arbitrary code.  This assertion will FAIL on the current vulnerable code
    because pickle.loads IS called with the raw decoded cookie bytes.
    """
    with patch("app.sessions.pickle.loads", wraps=pickle.loads) as mock_pickle_loads:
        load_session(pickle_cookie)

        # SECURE behavior: pickle.loads must NEVER be called with
        # attacker-supplied data.  If the assertion below fails, it means
        # pickle.loads WAS called — the vulnerability is confirmed.
        assert not mock_pickle_loads.called, (
            "VULNERABILITY CONFIRMED: load_session() invoked pickle.loads() on "
            "untrusted cookie data. An attacker can craft a cookie that executes "
            "arbitrary Python code during deserialization (CWE-502)."
        )


def test_load_session_uses_safe_deserializer(pickle_cookie):
    """RED: load_session() should use a safe deserializer (e.g. json.loads),
    not pickle, so that executable code embedded in a cookie cannot run.

    This test asserts the POSITIVE secure property: the safe path is taken.
    It will FAIL on the current code because json is not imported or used.
    """
    import json

    with patch("app.sessions.pickle.loads", side_effect=AssertionError(
        "pickle.loads must not be called — use a safe deserializer"
    )):
        # If the implementation is safe, it won't call pickle.loads at all.
        # On the vulnerable code this raises AssertionError via the side_effect,
        # but that is caught here so we can emit a clearer failure message.
        try:
            load_session(pickle_cookie)
        except AssertionError:
            pytest.fail(
                "VULNERABILITY CONFIRMED: load_session() called pickle.loads() "
                "instead of a safe deserializer. Attacker-controlled cookies can "
                "execute arbitrary code."
            )
