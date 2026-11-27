
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]

print("=" * 70)
print("IOT SENTINEL - FINAL SOURCE FORMATTING CLEANUP")
print("=" * 70)


def git_command(*args):
    return subprocess.run(
        ["git", *args],
        cwd=ROOT,
        capture_output=True,
        check=True,
    ).stdout


# Include both staged and unstaged source changes.
staged = git_command(
    "diff",
    "--cached",
    "--name-only",
    "--diff-filter=ACMR",
    "-z",
)

unstaged = git_command(
    "diff",
    "--name-only",
    "--diff-filter=ACMR",
    "-z",
)

files = sorted(
    set(
        staged.decode("utf-8").split("\0")
        + unstaged.decode("utf-8").split("\0")
    )
)

allowed_extensions = {
    ".py",
    ".ts",
    ".html",
    ".scss",
    ".css",
    ".md",
}

updated = []

for filename in files:

    if not filename:
        continue

    path = ROOT / filename

    if not path.is_file():
        continue

    if path.suffix not in allowed_extensions:
        continue

    original = path.read_bytes()

    content = original.decode("utf-8")

    newline = "\r\n" if "\r\n" in content else "\n"

    # Remove unnecessary blank lines at the end of the file.
    cleaned = content.rstrip("\r\n \t") + newline

    updated_bytes = cleaned.encode("utf-8")

    if original != updated_bytes:

        path.write_bytes(updated_bytes)

        updated.append(filename)

        print(f"PASS: Cleaned {filename}")

# Restage only files changed by this cleanup.
if updated:

    subprocess.run(
        ["git", "add", "--", *updated],
        cwd=ROOT,
        check=True,
    )

print("=" * 70)
print(f"Files corrected: {len(updated)}")
print("FORMATTING CLEANUP COMPLETED")
print("=" * 70)
