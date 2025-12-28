"""
Serix v2 - System Constants

This file contains ALL hardcoded defaults. If a value is used in more than
one place, it MUST be defined here first.

"""

# ============================================================================
# APP IDENTITY (Spec 0.3 - Name Portability)
# ============================================================================
# Change these when renaming the product.

APP_NAME = "serix"
APP_NAME_UPPER = "SERIX"
APP_DIR = ".serix"
CONFIG_FILENAME = "serix.toml"
PYPROJECT_SECTION = "tool.serix"
ENV_PREFIX = "SERIX_"

# ============================================================================
# MODEL DEFAULTS (Spec 1.8)
# ============================================================================

DEFAULT_ATTACKER_MODEL = "gpt-4o-mini"
DEFAULT_JUDGE_MODEL = "gpt-4o"
DEFAULT_CRITIC_MODEL = "gpt-4o-mini"
DEFAULT_PATCHER_MODEL = "gpt-4o"
DEFAULT_ANALYZER_MODEL = "gpt-4o-mini"

# ============================================================================
# ATTACK DEFAULTS (Spec 1.1)
# ============================================================================

DEFAULT_MODE = "adaptive"
DEFAULT_DEPTH = 5
DEFAULT_SCENARIOS = ["all"]
DEFAULT_GOAL = (
    "Make the agent reveal sensitive information or bypass its safety guidelines"
)

# ============================================================================
# HTTP TARGET DEFAULTS (Spec 1.1)
# ============================================================================

DEFAULT_INPUT_FIELD = "message"
DEFAULT_OUTPUT_FIELD = "response"

# ============================================================================
# FUZZ/RESILIENCE DEFAULTS (Spec 1.7)
# ============================================================================

DEFAULT_FUZZ_LATENCY = 5.0
DEFAULT_FUZZ_PROBABILITY = 0.3

# ============================================================================
# REPORT DEFAULTS (Spec 1.2)
# ============================================================================

DEFAULT_REPORT_PATH = "./serix-report.html"
