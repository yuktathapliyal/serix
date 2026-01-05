"""
Serix v2 - CLI Theme

Color palette and grid constants for CLI UI.
Centralized here for maintainability and reuse.

Law 2 Compliance: This is in cli/, so Rich imports allowed.
"""

from rich_gradient.text import Text as GradientText

# =============================================================================
# Color Palette
# =============================================================================

# Brand gradient colors: Vibrant Pink → Rich Purple
# Clean, premium, memorable - intentional 2-color gradient
BRAND_GRADIENT_COLORS = ["#ff375f", "#bf5af2"]  # Pink → Purple

# Semantic colors
COLOR_COMMAND = "#f8f4ff bold"  # Magnolia + bold - actionable items users type
COLOR_GOAL = "#e0c8a0"  # Soft Amber - gold undertone, premium warmth
COLOR_DIM = "#a8a0b0"  # Silver Purple - warm gray with purple undertone
COLOR_SUBTITLE = "#b8b0c0"  # Lifted Silver - header-level muted, above body text
COLOR_URL = (
    "#a8a0b0 underline"  # Silver Purple - blends with palette, underline for affordance
)

# =============================================================================
# Grid System
# =============================================================================

GLOBAL_MARGIN = 2  # Left margin for brand, tagline, section headers
ITEM_INDENT = 4  # Indent for items inside sections
FIRST_COL_WIDTH = 28  # Width of command/option column
MASTER_LANE = 30  # Column where descriptions start (28 + 2 padding)
OVERFLOW_THRESHOLD = 28  # Commands >= this length go to next line
CONTENT_WIDTH = 90  # Total content width (aligns subtitle with longest description)

# =============================================================================
# Brand Content
# =============================================================================

BRAND_TEXT = "S E R I X"
SUBTITLE_TEXT = "Agent Security Testing"
TAGLINE_LINES: list[str] = [
    "Find vulnerabilities in your AI agents before attackers do.",
    "Audit your agents, generate instant fixes, and export security reports.",
]
DOCS_URL = "https://github.com/yuktathapliyal/serix"

# =============================================================================
# Helper Functions
# =============================================================================


def create_gradient_brand() -> GradientText:
    """Create S E R I X with smooth gradient using rich-gradient.

    Uses GradientText for a mathematically smooth color transition
    from Magenta (#ff006e) to Purple (#7d56f4).
    """
    return GradientText(
        BRAND_TEXT, colors=BRAND_GRADIENT_COLORS, style="bold bright_white"
    )
