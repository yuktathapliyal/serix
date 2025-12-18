"""Thin wrappers for LangChain and CrewAI.

Imports are lazy so users without these frameworks won't get ImportError.
"""


def test_langchain(*args, **kwargs):
    """Wrap a LangChain agent for Serix testing. See langchain.py for details."""
    from serix.integrations.langchain import test_langchain as _test_langchain

    return _test_langchain(*args, **kwargs)


def test_crewai(*args, **kwargs):
    """Wrap a CrewAI crew for Serix testing. See crewai.py for details."""
    from serix.integrations.crewai import test_crewai as _test_crewai

    return _test_crewai(*args, **kwargs)


__all__ = ["test_langchain", "test_crewai"]
