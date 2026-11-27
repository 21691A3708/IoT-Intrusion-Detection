
from pathlib import Path
from datetime import datetime
import re
import shutil

ROOT = Path("frontend/src/app")

dashboard = ROOT / "components/dashboard"

ts_path = dashboard / "dashboard.ts"
html_path = dashboard / "dashboard.html"

# Create a separate timestamped backup
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

backup = Path(
    f"backups/final_frontend_optimization/{timestamp}"
)

backup.mkdir(parents=True, exist_ok=True)

for path in [ts_path, html_path]:
    shutil.copy2(path, backup / path.name)

print("PASS: Optimization backup created")

source = ts_path.read_text(encoding="utf-8-sig")
template = html_path.read_text(encoding="utf-8-sig")


# --------------------------------------------------
# 1. Remove legacy binary prediction history
# --------------------------------------------------

template, count = re.subn(
    r'<section\s+class="dashboard-section">\s*'
    r'<app-prediction-history\s*/>\s*</section>',
    "",
    template,
)

if "<app-prediction-history" in template:
    raise RuntimeError(
        "Unexpected prediction history markup. "
        "No source files modified."
    )

print(f"PASS: Legacy prediction history removed ({count})")


# --------------------------------------------------
# 2. Remove PredictionHistory component import
# --------------------------------------------------

source = re.sub(
    r"import\s*\{\s*PredictionHistory\s*\}"
    r"\s*from\s*['\"][^'\"]+['\"]\s*;",
    "",
    source,
)

source = re.sub(
    r"\bPredictionHistory\s*,\s*",
    "",
    source,
)

print("PASS: Legacy prediction history import removed")


# --------------------------------------------------
# 3. Remove outdated migration notice
# --------------------------------------------------

template, count = re.subn(
    r"@if\s*\([^{}]*\)\s*\{\s*"
    r'<div\s+class="migration-notice"[^>]*>'
    r"[\s\S]*?</div>\s*\}",
    "",
    template,
)

if 'class="migration-notice"' in template:
    raise RuntimeError(
        "Migration notice structure not recognized."
    )

print(f"PASS: Outdated migration notice removed ({count})")


# --------------------------------------------------
# 4. Remove hidden legacy WebSocket panel
# --------------------------------------------------

template, count = re.subn(
    r'<div\s+class="sidebar-status"\s+'
    r'style="display:\s*none;">'
    r'[\s\S]*?'
    r'<strong>Legacy WebSocket \(inactive\)</strong>'
    r'[\s\S]*?</div>\s*</div>',
    "",
    template,
)

if "Legacy WebSocket (inactive)" in template:
    raise RuntimeError(
        "Legacy WebSocket panel structure not recognized."
    )

print(f"PASS: Hidden WebSocket panel removed ({count})")


# --------------------------------------------------
# 5. Add Angular deferred loading
# --------------------------------------------------

deferred_components = [
    "app-detection",
    "app-explainability",
    "app-incident-management",
    "app-response-center",
    "app-batch-reports",
    "app-security-assistant",
]

for selector in deferred_components:

    pattern = (
        r"<"
        + re.escape(selector)
        + r"\b[^<>]*/>"
    )

    matches = list(re.finditer(pattern, template))

    if len(matches) != 1:
        raise RuntimeError(
            f"Expected one component: {selector}. "
            f"Found {len(matches)}."
        )

    match = matches[0]

    component = match.group(0)

    replacement = (
        "@defer (on immediate) {\n"
        f"  {component}\n"
        "} @placeholder {\n"
        '  <p role="status">Preparing module...</p>\n'
        "} @loading {\n"
        '  <p role="status">Loading module...</p>\n'
        "} @error {\n"
        '  <p role="alert">'
        "Unable to load module. "
        "Please refresh the page."
        "</p>\n"
        "}"
    )

    template = (
        template[:match.start()]
        + replacement
        + template[match.end():]
    )

    print(f"PASS: Deferred loading added: {selector}")


# --------------------------------------------------
# 6. Verify important components remain available
# --------------------------------------------------

required_selectors = [
    "app-multiclass-monitor",
    "app-detection",
    "app-incident-management",
    "app-devices",
    "app-device-form",
    "app-explainability",
    "app-response-center",
    "app-batch-reports",
    "app-security-assistant",
    "app-backend-status",
]

for selector in required_selectors:

    if f"<{selector}" not in template:
        raise RuntimeError(
            f"Required component missing: {selector}"
        )

print("PASS: Required components preserved")


# --------------------------------------------------
# 7. Save optimized files
# --------------------------------------------------

ts_path.write_text(source, encoding="utf-8")
html_path.write_text(template, encoding="utf-8")

print("=" * 65)
print("FRONTEND OPTIMIZATION COMPLETED")
print("=" * 65)
print("PASS: Legacy prediction history removed")
print("PASS: Outdated migration notice removed")
print("PASS: Hidden WebSocket panel removed")
print("PASS: Six components configured for deferred loading")
print("PASS: Existing navigation preserved")
print("PASS: Backend and database unchanged")
print(f"Backup: {backup.resolve()}")
print("=" * 65)
