"""
Serix v2 - Target Implementations

Concrete implementations of the Target protocol for attacking:
- Python functions/methods (PythonFunctionTarget)
- HTTP endpoints (HTTPTarget)

Law 3: These implementations satisfy the Target protocol from core/protocols.py
"""

from serix_v2.targets.factory import resolve_target
from serix_v2.targets.http_target import HTTPTarget
from serix_v2.targets.python_target import PythonFunctionTarget

__all__ = [
    "PythonFunctionTarget",
    "HTTPTarget",
    "resolve_target",
]
