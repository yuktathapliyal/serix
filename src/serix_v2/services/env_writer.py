"""
Serix v2 - Environment File Writer Service

Handles writing API keys to .env files and updating .gitignore.

Law 2: CLI-is-a-Guest - This is a service, so NO typer/rich/click imports.
Returns Pydantic result objects for CLI to display.
"""

from pathlib import Path

from pydantic import BaseModel


class EnvWriteResult(BaseModel):
    """Result of writing to .env file."""

    success: bool
    action: str  # "created", "appended", "exists"
    path: str
    error_message: str | None = None


class GitignoreResult(BaseModel):
    """Result of updating .gitignore."""

    success: bool
    action: str  # "added", "exists", "created"
    error_message: str | None = None


def append_to_env(
    key_name: str,
    key_value: str,
    env_path: Path | None = None,
) -> EnvWriteResult:
    """
    Add an API key to .env file.

    Creates the file if it doesn't exist. Appends if it exists.
    If the key already exists in the file, it will NOT be overwritten
    (returns exists action).

    Args:
        key_name: Environment variable name (e.g., "OPENAI_API_KEY")
        key_value: The API key value
        env_path: Path to .env file. Defaults to .env in current directory.

    Returns:
        EnvWriteResult with operation status
    """
    if env_path is None:
        env_path = Path(".env")

    try:
        # Check if file exists and if key is already present
        if env_path.exists():
            content = env_path.read_text()
            # Check if key already exists (with = sign to avoid partial matches)
            if f"{key_name}=" in content or f"{key_name} =" in content:
                return EnvWriteResult(
                    success=True,
                    action="exists",
                    path=str(env_path),
                )

            # Append to existing file
            # Ensure we start on a new line
            if content and not content.endswith("\n"):
                content += "\n"

            env_path.write_text(content + f"{key_name}={key_value}\n")
            return EnvWriteResult(
                success=True,
                action="appended",
                path=str(env_path),
            )
        else:
            # Create new file
            env_path.write_text(f"{key_name}={key_value}\n")
            return EnvWriteResult(
                success=True,
                action="created",
                path=str(env_path),
            )

    except PermissionError:
        return EnvWriteResult(
            success=False,
            action="failed",
            path=str(env_path),
            error_message="Permission denied writing to .env",
        )
    except OSError as e:
        return EnvWriteResult(
            success=False,
            action="failed",
            path=str(env_path),
            error_message=f"Error writing to .env: {e}",
        )


def ensure_gitignore_env(gitignore_path: Path | None = None) -> GitignoreResult:
    """
    Ensure .env is in .gitignore to prevent accidental commits.

    Creates .gitignore if it doesn't exist.

    Args:
        gitignore_path: Path to .gitignore. Defaults to .gitignore in current directory.

    Returns:
        GitignoreResult with operation status
    """
    if gitignore_path is None:
        gitignore_path = Path(".gitignore")

    try:
        if gitignore_path.exists():
            content = gitignore_path.read_text()
            lines = content.splitlines()

            # Check if .env is already in gitignore
            for line in lines:
                stripped = line.strip()
                if stripped == ".env" or stripped == "/.env":
                    return GitignoreResult(
                        success=True,
                        action="exists",
                    )

            # Add .env to existing file
            if content and not content.endswith("\n"):
                content += "\n"

            # Add with a comment
            gitignore_path.write_text(content + "\n# API keys (added by serix)\n.env\n")
            return GitignoreResult(
                success=True,
                action="added",
            )
        else:
            # Create new .gitignore with .env entry
            gitignore_path.write_text("# API keys (added by serix)\n.env\n")
            return GitignoreResult(
                success=True,
                action="created",
            )

    except PermissionError:
        return GitignoreResult(
            success=False,
            action="failed",
            error_message="Permission denied writing to .gitignore",
        )
    except OSError as e:
        return GitignoreResult(
            success=False,
            action="failed",
            error_message=f"Error writing to .gitignore: {e}",
        )


def set_env_in_process(key_name: str, key_value: str) -> None:
    """
    Set environment variable in the current process.

    This allows the key to be used immediately after being added to .env
    without requiring a restart.

    Args:
        key_name: Environment variable name
        key_value: The value to set
    """
    import os

    os.environ[key_name] = key_value
