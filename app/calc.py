"""A tiny calculator. Uses a safe AST-based evaluator instead of eval()
to prevent arbitrary code execution (CWE-94/CWE-95).
"""

import ast
import operator


_SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _safe_eval(node):
    if isinstance(node, ast.Expression):
        return _safe_eval(node.body)
    elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return node.value
    elif isinstance(node, ast.BinOp):
        op_type = type(node.op)
        if op_type not in _SAFE_OPERATORS:
            raise ValueError(f"Unsupported operator: {op_type.__name__}")
        left = _safe_eval(node.left)
        right = _safe_eval(node.right)
        return _SAFE_OPERATORS[op_type](left, right)
    elif isinstance(node, ast.UnaryOp):
        op_type = type(node.op)
        if op_type not in _SAFE_OPERATORS:
            raise ValueError(f"Unsupported operator: {op_type.__name__}")
        operand = _safe_eval(node.operand)
        return _SAFE_OPERATORS[op_type](operand)
    else:
        raise ValueError(f"Unsupported expression type: {type(node).__name__}")


def calculate(expression):
    try:
        tree = ast.parse(expression, mode='eval')
    except SyntaxError as e:
        raise ValueError(f"Invalid expression: {e}") from e
    result = _safe_eval(tree)
    return result
