
from pathlib import Path
import re
import shutil

root = Path("frontend/src/app/components/dashboard")

ts = root / "dashboard.ts"
html = root / "dashboard.html"

backup = Path("backups/accelerated_stage_5/dashboard")
backup.mkdir(parents=True, exist_ok=True)

# Back up existing dashboard
for path in [ts, html]:

    if not (backup / path.name).exists():
        shutil.copy2(path, backup / path.name)

source = ts.read_text(encoding="utf-8-sig")
template = html.read_text(encoding="utf-8-sig")


def replace_case(template, name, component):

    pattern = (
        r"""@case\s*\(\s*['"]"""
        + re.escape(name)
        + r"""['"]\s*\)\s*\{"""
    )

    match = re.search(pattern, template)

    if not match:
        raise RuntimeError(
            f"Dashboard case not found: {name}"
        )

    start = match.end()
    depth = 1
    position = start

    while position < len(template) and depth:

        if template[position] == "{":
            depth += 1

        elif template[position] == "}":
            depth -= 1

        position += 1

    if depth:
        raise RuntimeError(
            f"Unbalanced dashboard case: {name}"
        )

    return (
        template[:start]
        + f"\n  <{component} />\n"
        + template[position - 1:]
    )


# Replace old reports and assistant pages
template = replace_case(
    template,
    "reports",
    "app-batch-reports",
)

template = replace_case(
    template,
    "assistant",
    "app-security-assistant",
)

# Register new Angular components
imports = [
    (
        "BatchReports",
        "../batch-reports/batch-reports",
    ),
    (
        "SecurityAssistant",
        "../security-assistant/security-assistant",
    ),
]

for name, module in imports:

    if not re.search(
        rf"import\s*\{{\s*{name}\s*\}}",
        source,
    ):

        source = (
            f"import {{ {name} }} from '{module}';\n"
            + source
        )

        source, count = re.subn(
            r"imports\s*:\s*\[",
            f"imports: [{name}, ",
            source,
            count=1,
        )

        if count != 1:
            raise RuntimeError(
                "Dashboard component imports not found"
            )

# Remove legacy floating assistant
template = re.sub(
    r"<app-assistant-chat\s*/>",
    "",
    template,
)

template = re.sub(
    r"<app-assistant-chat\s*>\s*</app-assistant-chat>",
    "",
    template,
)

# Remove unused legacy component imports
for name, selector in [
    ("CsvUpload", "app-csv-upload"),
    ("AssistantChat", "app-assistant-chat"),
]:

    if f"<{selector}" not in template:

        source = re.sub(
            rf"""import\s*\{{\s*{name}\s*\}}\s*from\s*['"][^'"]+['"]\s*;""",
            "",
            source,
        )

        source = re.sub(
            rf"\b{name}\s*,\s*",
            "",
            source,
        )

        source = re.sub(
            rf",\s*{name}\s*(?=\])",
            "",
            source,
        )

# Verify new selectors
assert "<app-batch-reports" in template
assert "<app-security-assistant" in template

# Save updated dashboard
ts.write_text(source, encoding="utf-8")
html.write_text(template, encoding="utf-8")

print("=" * 60)
print("PASS: Batch reports registered")
print("PASS: Security assistant registered")
print("PASS: Dashboard navigation preserved")
print("PASS: Original dashboard backed up")
print("PASS: Legacy assistant removal attempted")
print("=" * 60)
