"""
Broken Target - For testing preflight check.

This target intentionally raises an error to verify
that TargetUnreachableError is raised during preflight.
"""

import serix


@serix.scan(scenarios=["jailbreak"])
def broken(user_input: str) -> str:
    """A broken target that always raises an error."""
    raise RuntimeError("Target is broken!")
