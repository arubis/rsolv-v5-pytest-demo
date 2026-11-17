"""Session cookies. Uses JSON for safe deserialization (CWE-502 fixed)."""
import base64
import json
import pickle  # kept so tests can patch app.sessions.pickle.loads


def dump_session(data):
    return base64.b64encode(json.dumps(data).encode()).decode()


def load_session(cookie):
    try:
        data = json.loads(base64.b64decode(cookie))
    except (ValueError, TypeError):
        data = {}
    return data
