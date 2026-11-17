"""RED test: eval() in calculate() must not execute arbitrary Python code (CWE-95).

A secure implementation should restrict input to safe mathematical expressions
and raise an error (or otherwise reject) any expression that attempts arbitrary
code execution.  On the current vulnerable code the assertions FAIL because
eval() happily runs whatever Python it is given.
"""

import pytest
from unittest.mock import patch
from app.calc import calculate


# ---------------------------------------------------------------------------
# Mechanism-level: eval() must NOT be called with user-supplied input
# ---------------------------------------------------------------------------

def test_eval_is_not_called_with_user_input():
    """The calculate() function must not pass user input to eval().

    RED: fails on the vulnerable code because eval() is called directly with
    the expression string.
    GREEN: passes after fix because the dangerous eval() path is removed.
    """
    with patch('builtins.eval', return_value=42) as mock_eval:
        try:
            calculate("2 + 2")
        except Exception:
            pass  # Acceptable — a safe parser may raise for some inputs

        assert not mock_eval.called, (
            "calculate() passed user input to eval() — arbitrary code injection "
            "is possible (CWE-95)."
        )


# ---------------------------------------------------------------------------
# Property-level: code-injection payloads must NOT succeed
# ---------------------------------------------------------------------------

def test_calculate_rejects_dunder_import_payload():
    """Arbitrary Python via __import__ must not be executed.

    A secure calculator should raise an error when given an expression that
    tries to import a module.  On the vulnerable code eval() executes it
    successfully instead, so pytest.raises() is NOT satisfied and the test fails.
    """
    with pytest.raises(Exception):
        calculate("__import__('os').getcwd()")


def test_calculate_rejects_attribute_access_on_builtins():
    """Accessing __class__ or other dunder attributes is not a math expression.

    A secure implementation must reject expressions that walk the object
    hierarchy to reach dangerous builtins.
    """
    with pytest.raises(Exception):
        calculate("().__class__.__bases__[0].__subclasses__()")


def test_calculate_injection_does_not_return_non_numeric_value():
    """The result of a code-injection attempt must never be a non-numeric value.

    On the current vulnerable code, calculate("__import__('os').getcwd()")
    returns a string (the current working directory), proving that arbitrary
    code ran.  A secure implementation either raises or returns a number.
    """
    try:
        result = calculate("__import__('os').getcwd()")
    except Exception:
        # Raising is the correct secure behaviour – test passes.
        return

    # If no exception was raised the implementation is vulnerable: it returned
    # whatever the injected code produced.  Assert that the result is numeric;
    # this will FAIL because getcwd() returns a string.
    assert isinstance(result, (int, float)), (
        f"calculate() executed injected code and returned a non-numeric value: {result!r}. "
        "Arbitrary code injection via eval() is possible."
    )
