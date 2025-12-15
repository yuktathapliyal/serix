# Module 4: Reporting Engine - Development Log

**Date:** December 14, 2024
**Module:** M4 - Reporting Engine
**Status:** COMPLETE

---

## What We Established

**Goal:** Build a comprehensive reporting engine that transforms Module 3's EvaluationResult into beautiful, shareable HTML reports and machine-readable JSON exports for CI/CD integration.

**Problem We Solved:** Module 3 gave us detailed security scores and vulnerability classifications, but that data was only available in the console. Teams needed:
- Shareable reports for stakeholders who don't run CLI tools
- JSON exports for CI/CD pipeline integration
- GitHub Actions integration for automated PR feedback

---

## What We Built

### 1. JSON Export (`src/serix/report/json_export.py`)

Machine-readable JSON output for CI/CD pipelines:

```python
@dataclass
class SerixReport:
    version: str  # "1.0"
    timestamp: str  # ISO format
    target: str
    passed: bool
    scores: dict[str, int]  # overall, safety, compliance, etc.
    vulnerabilities: list[dict]
    conversation: list[dict]
    remediations: list[dict]
    metadata: dict
```

**Key Functions:**
- `export_json()` - Write evaluation to JSON file
- `to_dict()` - Convert to dictionary for serialization
- `create_report()` - Create SerixReport dataclass

### 2. GitHub Actions Integration (`src/serix/report/github.py`)

Automatic integration with GitHub Actions:

```python
def write_github_output(evaluation, target) -> bool:
    """Auto-write to $GITHUB_OUTPUT and $GITHUB_STEP_SUMMARY."""
```

**Output Variables (written to $GITHUB_OUTPUT):**
```
passed=false
overall_score=45
safety_score=60
compliance_score=40
info_leakage_score=30
role_adherence_score=55
vulnerability_count=1
critical_count=1
high_count=0
```

**Step Summary:** Automatically generates a markdown table with scores and vulnerabilities for the GitHub Actions UI.

### 3. Enhanced HTML Report (`src/serix/report/html.py`)

New evaluation-aware report generation:

```python
@dataclass
class EvaluationReportData:
    # Scores
    overall_score: int
    safety_score: int
    compliance_score: int
    info_leakage_score: int
    role_adherence_score: int

    # Vulnerabilities
    vulnerabilities: list[VulnerabilityReportData]

    # Remediations
    remediations: list[RemediationReportData]

    # Attack transcript
    conversation: list[ConversationMessage]
```

### 4. Updated HTML Template (`src/serix/report/templates/report.html`)

New visual components:

**Score Gauges:**
- CSS-only circular progress gauges using `conic-gradient`
- Color-coded by score range (green/yellow/orange/red)
- Large overall score + 4 axis gauges

**Vulnerability Cards:**
- Severity-colored borders (critical=red, high=orange, etc.)
- Expandable evidence sections
- OWASP-style type badges

**Remediation Blocks:**
- Python syntax highlighting (inline CSS, no dependencies)
- Copy-to-clipboard buttons
- Reference links

**Conversation Transcript:**
- Attacker/agent role highlighting
- Turn numbering
- Monospace formatting

### 5. CLI Enhancements (`src/serix/cli.py`)

New flags for the `serix test` command:

```bash
# Generate HTML report
serix test agent.py:func --scenarios jailbreak --report report.html

# Generate JSON report
serix test agent.py:func --scenarios jailbreak --json-report results.json

# Both reports
serix test agent.py:func --scenarios jailbreak \
  --report report.html \
  --json-report results.json

# GitHub Actions mode
serix test agent.py:func --scenarios jailbreak --github
```

---

## Architecture

```
EvaluationResult (M3)
        │
        ├──→ generate_evaluation_report() → HTML file
        │    └── report.html template
        │        ├── Score gauges (CSS conic-gradient)
        │        ├── Vulnerability cards
        │        ├── Remediation blocks (syntax highlighted)
        │        └── Attack transcript
        │
        ├──→ export_json() → JSON file
        │    └── SerixReport schema
        │
        └──→ write_github_output() → CI/CD
             ├── $GITHUB_OUTPUT (key=value pairs)
             └── $GITHUB_STEP_SUMMARY (markdown)
```

---

## Files Created/Modified

**New Files:**
- `src/serix/report/json_export.py` - JSON serialization
- `src/serix/report/github.py` - GitHub Actions integration

**Modified Files:**
- `src/serix/report/html.py` - Added EvaluationReportData, generate_evaluation_report()
- `src/serix/report/templates/report.html` - Score gauges, vuln cards, remediations
- `src/serix/report/__init__.py` - New exports
- `src/serix/cli.py` - --json-report, --github flags

---

## Design Decisions

### 1. Inline CSS Syntax Highlighting

**Choice:** Self-contained CSS-based Python highlighting with no external dependencies

**Rationale:**
- Reports should be truly shareable (no CDN dependencies)
- Simple regex-based highlighting for common Python constructs
- Smaller file size than including full highlight.js

**Implementation:**
```python
def highlight_python_code(code: str) -> str:
    """Apply inline CSS syntax highlighting."""
    # Keywords, strings, comments, functions, decorators
    # All using <span class="hl-*"> tags
```

### 2. CSS-Only Score Gauges

**Choice:** `conic-gradient` CSS for circular progress

**Rationale:**
- No JavaScript required
- Works in all modern browsers
- Smooth, professional appearance

**Implementation:**
```css
.gauge-circle::before {
    background: conic-gradient(
        var(--gauge-color) calc(var(--score) * 3.6deg),
        var(--bg-hover) calc(var(--score) * 3.6deg)
    );
    mask: radial-gradient(...);  /* Creates ring shape */
}
```

### 3. Template Backwards Compatibility

**Choice:** Use `{% if report.is_evaluation_report %}` to detect report type

**Rationale:**
- Existing `serix attack` command still works with old report format
- Single template file, two rendering modes
- No breaking changes

---

## Usage Examples

### Basic HTML Report
```bash
serix test examples/decorated_agent.py:customer_service_agent \
  --scenarios jailbreak \
  --report security-report.html
```

### JSON for CI/CD
```bash
serix test agent.py:my_agent \
  --scenarios injection,data_leak \
  --json-report results.json

# Then in CI:
jq '.passed' results.json  # true/false
jq '.scores.overall' results.json  # 0-100
```

### GitHub Actions Workflow
```yaml
- name: Security Scan
  run: |
    serix test agent.py:my_agent \
      --scenarios jailbreak,injection \
      --github \
      --report report.html

- name: Upload Report
  uses: actions/upload-artifact@v3
  with:
    name: security-report
    path: report.html
```

---

## What's Next (Future)

1. **PDF Export** - For formal security audits
2. **Trend Charts** - Compare scores across runs
3. **Slack/Teams Integration** - Webhook notifications
4. **Custom Report Themes** - Branding options
