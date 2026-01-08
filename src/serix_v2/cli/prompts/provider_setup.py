"""
Serix v2 - Provider Setup Wizard

Interactive prompts for configuring LLM providers.

Law 2 Compliance: This is in cli/, so typer/rich allowed.
Uses pure Python services from services/ for actual operations.
"""

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from serix_v2.cli.theme import COLOR_DIM, COLOR_ERROR, COLOR_SUCCESS
from serix_v2.core.constants import PROVIDER_CONSOLE_URLS, PROVIDER_ENV_VARS
from serix_v2.services.env_writer import (
    append_to_env,
    ensure_gitignore_env,
    set_env_in_process,
)
from serix_v2.services.key_validator import validate_key

console = Console()


def prompt_provider_selection() -> str | None:
    """
    Prompt user to select an LLM provider.

    Returns:
        Provider name ("openai", "anthropic", "google") or None if user chooses manual setup.
    """
    panel_content = """
  Let's set up your LLM provider.

  Which provider do you want to use?

    [1] OpenAI      gpt-4o, gpt-4o-mini
    [2] Anthropic   Claude Sonnet 4, Claude Haiku 4
    [3] Google      Gemini Pro, Gemini Flash
    [4] Configure manually (advanced)
"""
    console.print()
    console.print(
        Panel(panel_content, title="Welcome to Serix", border_style=COLOR_DIM)
    )

    choice = Prompt.ask("Select [1-4]", default="1")

    if choice == "1":
        return "openai"
    elif choice == "2":
        return "anthropic"
    elif choice == "3":
        return "google"
    elif choice == "4":
        return None
    else:
        console.print(
            f"[{COLOR_ERROR}]Invalid choice. Please select 1-4.[/{COLOR_ERROR}]"
        )
        return prompt_provider_selection()


def prompt_api_key_entry(provider: str) -> str | None:
    """
    Prompt user to enter and validate an API key.

    Args:
        provider: Provider name ("openai", "anthropic", "google")

    Returns:
        Validated API key, or None if user cancels.
    """
    console_url = PROVIDER_CONSOLE_URLS.get(provider, "")
    provider_title = provider.capitalize()

    panel_content = f"""
  Get your API key at: {console_url}
"""
    console.print()
    console.print(
        Panel(panel_content, title=f"{provider_title} Setup", border_style=COLOR_DIM)
    )

    while True:
        key = Prompt.ask("Paste your API key", password=True)

        if not key or not key.strip():
            console.print(f"[{COLOR_ERROR}]No key entered.[/{COLOR_ERROR}]")
            if not Confirm.ask("Try again?", default=True):
                return None
            continue

        key = key.strip()

        # Strip accidental ENV_VAR= prefix (user may paste whole line from .env)
        env_var = PROVIDER_ENV_VARS.get(provider, f"{provider.upper()}_API_KEY")
        if key.startswith(f"{env_var}="):
            key = key[len(f"{env_var}=") :]

        # Validate the key
        console.print("  Validating... ", end="")
        result = validate_key(provider, key)

        if result.valid:
            console.print(f"[{COLOR_SUCCESS}]Key works![/{COLOR_SUCCESS}]")
            return key
        else:
            console.print(f"[{COLOR_ERROR}]{result.error_message}[/{COLOR_ERROR}]")
            _render_validation_failure(provider)

            if not Confirm.ask("Try again?", default=True):
                return None


def _render_validation_failure(provider: str) -> None:
    """Render helpful message when key validation fails."""
    console_url = PROVIDER_CONSOLE_URLS.get(provider, "")

    panel_content = f"""
  The API key didn't work. Common issues:

    - Key was copied incorrectly (try again)
    - Key has been revoked
    - Key doesn't have required permissions

  Get a new key at: {console_url}
"""
    console.print(
        Panel(panel_content, title="Key Validation Failed", border_style=COLOR_ERROR)
    )


def handle_missing_key(provider: str) -> bool:
    """
    Handle case when provider is specified but key is missing.

    Shows interactive prompt to enter key or manual setup instructions.

    Args:
        provider: Provider name

    Returns:
        True if key was successfully added and validated, False otherwise.
    """
    console_url = PROVIDER_CONSOLE_URLS.get(provider, "")
    provider_title = provider.capitalize()

    panel_content = f"""
  Get a key at: {console_url}

    [1] Enter API key now
    [2] I'll set it up manually
"""
    console.print()
    console.print(
        Panel(
            panel_content,
            title=f"{provider_title} API Key Required",
            border_style=COLOR_DIM,
        )
    )

    choice = Prompt.ask("Select [1-2]", default="1")

    if choice == "1":
        key = prompt_api_key_entry(provider)
        if key:
            return _save_key(provider, key)
        return False
    else:
        _render_manual_setup(provider)
        return False


def _save_key(provider: str, key: str) -> bool:
    """
    Save validated API key to .env file and set in current process.

    Args:
        provider: Provider name
        key: Validated API key

    Returns:
        True if successfully saved, False otherwise.
    """
    env_var = PROVIDER_ENV_VARS.get(provider, f"{provider.upper()}_API_KEY")

    # Write to .env
    env_result = append_to_env(env_var, key)
    if not env_result.success:
        console.print(f"[{COLOR_ERROR}]{env_result.error_message}[/{COLOR_ERROR}]")
        return False

    # Update .gitignore
    gitignore_result = ensure_gitignore_env()

    # Set in current process for immediate use
    set_env_in_process(env_var, key)

    # Display results
    console.print()
    if env_result.action == "created":
        console.print(f"  [{COLOR_SUCCESS}]Created[/{COLOR_SUCCESS}] .env")
    elif env_result.action == "appended":
        console.print(f"  [{COLOR_SUCCESS}]Added to[/{COLOR_SUCCESS}] existing .env")
    else:
        console.print(f"  [{COLOR_DIM}]Key already in[/{COLOR_DIM}] .env")

    if gitignore_result.success and gitignore_result.action in ("added", "created"):
        console.print(f"  [{COLOR_SUCCESS}]Added[/{COLOR_SUCCESS}] .env to .gitignore")

    console.print()
    return True


def _render_manual_setup(provider: str) -> None:
    """Render manual setup instructions."""
    env_var = PROVIDER_ENV_VARS.get(provider, f"{provider.upper()}_API_KEY")
    console_url = PROVIDER_CONSOLE_URLS.get(provider, "")

    panel_content = f"""
  Get a key at: {console_url}

  Set your API key using one of these methods:

  Option A: Environment Variable
  ──────────────────────────────────────────
    export {env_var}=your-key-here

  Option B: .env File
  ──────────────────────────────────────────
    Add to .env in your project root:
      {env_var}=your-key-here

  Option C: serix.toml (provider only)
  ──────────────────────────────────────────
    provider = "{provider}"

  Then re-run:
    serix test your_agent.py:fn
"""
    console.print()
    console.print(Panel(panel_content, title="Manual Setup", border_style=COLOR_DIM))


def _render_advanced_config() -> None:
    """Render advanced configuration instructions."""
    panel_content = """
  Configure each model individually in serix.toml:

    [models]
    attacker = "claude-haiku-4-20250514"    # Anthropic
    critic   = "claude-haiku-4-20250514"    # Anthropic
    analyzer = "gpt-4o-mini"                # OpenAI
    judge    = "gpt-4o"                     # OpenAI
    patcher  = "gemini-1.5-pro"             # Google

  You'll need API keys for each provider used.

  Set in .env file:
    OPENAI_API_KEY=sk-...
    ANTHROPIC_API_KEY=sk-ant-...
    GOOGLE_API_KEY=...
"""
    console.print()
    console.print(
        Panel(panel_content, title="Advanced Configuration", border_style=COLOR_DIM)
    )


def run_full_onboarding() -> tuple[str | None, bool]:
    """
    Run full onboarding wizard when no API keys are found.

    Returns:
        Tuple of (provider_name, success). Provider is None if user chose manual setup.
    """
    provider = prompt_provider_selection()

    if provider is None:
        # User chose manual/advanced setup
        _render_advanced_config()
        return None, False

    # User chose a provider - get their API key
    key = prompt_api_key_entry(provider)

    if key:
        success = _save_key(provider, key)
        return provider, success

    return provider, False
