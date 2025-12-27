"""Output renderers for CLI."""

from .github import GithubRenderer, is_github_actions
from .static import StaticRenderer

__all__ = ["GithubRenderer", "StaticRenderer", "is_github_actions"]
