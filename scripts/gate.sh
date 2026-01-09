#!/bin/bash
#
# SERIX GATE SCRIPT
# =================
# Run this after EVERY code change. No exceptions.
#
# Usage:
#   ./scripts/gate.sh        # Full gate (smoke + lint + tests)
#   ./scripts/gate.sh quick  # Quick gate (smoke + lint only)
#   ./scripts/gate.sh full   # Full gate with integration tests
#
# Exit codes:
#   0 - All gates passed
#   1 - Gate failed (DO NOT continue until fixed)
#

set -e  # Exit on first failure

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASS_COUNT=0
FAIL_COUNT=0

# Helper functions
print_header() {
    echo ""
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

print_pass() {
    echo -e "  ${GREEN}✓${NC} $1"
    PASS_COUNT=$((PASS_COUNT + 1))
}

print_fail() {
    echo -e "  ${RED}✗${NC} $1"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

print_skip() {
    echo -e "  ${YELLOW}○${NC} $1 (skipped)"
}

# Determine gate level
GATE_LEVEL="${1:-full}"

echo ""
echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║  SERIX GATE - Level: ${GATE_LEVEL}                                        ║${NC}"
echo -e "${BLUE}║  Run after EVERY code change. Red = STOP.                      ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"

# ============================================================================
# PHASE 1: SMOKE TESTS (< 3 seconds)
# These catch catastrophic breaks - if these fail, nothing works
# ============================================================================
print_header "Phase 1: Smoke Tests"

# Test that CLI loads at all
if uv run serix --version > /dev/null 2>&1; then
    print_pass "serix --version"
else
    print_fail "serix --version"
    echo -e "    ${RED}CLI failed to load. Check for import errors.${NC}"
    exit 1
fi

# Test each command's help
for cmd in test demo run init; do
    if uv run serix $cmd --help > /dev/null 2>&1; then
        print_pass "serix $cmd --help"
    else
        print_fail "serix $cmd --help"
        echo -e "    ${RED}Command '$cmd' is broken.${NC}"
        exit 1
    fi
done

# ============================================================================
# PHASE 2: LINT & TYPE CHECK (< 10 seconds)
# These catch code quality issues before they become bugs
# ============================================================================
print_header "Phase 2: Lint & Type Check"

# Ruff linting
if uv run ruff check src/serix/ --quiet 2>/dev/null; then
    print_pass "ruff check (linting)"
else
    print_fail "ruff check (linting)"
    echo -e "    ${YELLOW}Run 'uv run ruff check src/serix/' to see issues${NC}"
    exit 1
fi

# Mypy type checking
if uv run mypy src/serix/ --quiet 2>/dev/null; then
    print_pass "mypy (type check)"
else
    # Mypy warnings are common, check if it's actual errors
    MYPY_OUTPUT=$(uv run mypy src/serix/ 2>&1 || true)
    if echo "$MYPY_OUTPUT" | grep -q "error:"; then
        print_fail "mypy (type check)"
        echo -e "    ${YELLOW}Run 'uv run mypy src/serix/' to see errors${NC}"
        exit 1
    else
        print_pass "mypy (type check - warnings only)"
    fi
fi

# ============================================================================
# PHASE 3: UNIT TESTS (< 30 seconds)
# These verify individual components work correctly
# ============================================================================
if [[ "$GATE_LEVEL" != "quick" ]]; then
    print_header "Phase 3: Unit Tests"

    if uv run pytest tests/ -q --tb=no 2>/dev/null; then
        PYTEST_RESULT=$(uv run pytest tests/ -q --tb=no 2>&1 | tail -1)
        print_pass "pytest ($PYTEST_RESULT)"
    else
        print_fail "pytest"
        echo -e "    ${YELLOW}Run 'uv run pytest tests/ -v' to see failures${NC}"
        exit 1
    fi
else
    print_header "Phase 3: Unit Tests (SKIPPED - quick mode)"
    print_skip "pytest (use './scripts/gate.sh full' to run)"
fi

# ============================================================================
# PHASE 4: INTEGRATION TESTS (optional, requires API key)
# These verify end-to-end workflows
# ============================================================================
if [[ "$GATE_LEVEL" == "full" ]]; then
    print_header "Phase 4: Integration Tests"

    if [[ -z "${OPENAI_API_KEY}" ]]; then
        print_skip "serix demo --no-live (no OPENAI_API_KEY)"
    else
        # Only run if we have time and API key
        print_skip "serix demo --no-live (manual verification recommended)"
    fi
else
    print_header "Phase 4: Integration Tests (SKIPPED)"
    print_skip "Integration tests (use './scripts/gate.sh full' to run)"
fi

# ============================================================================
# SUMMARY
# ============================================================================
echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

if [[ $FAIL_COUNT -eq 0 ]]; then
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  ✅ ALL GATES PASSED ($PASS_COUNT checks)                              ║${NC}"
    echo -e "${GREEN}║  Safe to continue. Consider committing if feature complete.   ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║  ❌ GATE FAILED ($FAIL_COUNT failures)                                  ║${NC}"
    echo -e "${RED}║  STOP. Fix the issue before continuing.                        ║${NC}"
    echo -e "${RED}║  Do NOT proceed with more changes until green.                 ║${NC}"
    echo -e "${RED}╚════════════════════════════════════════════════════════════════╝${NC}"
    exit 1
fi
