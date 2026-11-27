
from pathlib import Path
import json
import urllib.request
import subprocess
from datetime import datetime, timezone

ROOT = Path.cwd()
BASE_URL = "http://127.0.0.1:8000"

results = []


def check(name, passed, details=""):

    results.append({
        "name": name,
        "passed": bool(passed),
        "details": str(details),
    })

    status = "PASS" if passed else "FAIL"

    print(f"{status}: {name}")

    if details:
        print(f"      {details}")


def request(path):

    with urllib.request.urlopen(
        BASE_URL + path,
        timeout=30,
    ) as response:

        return json.load(response)


print("=" * 65)
print("IOT SENTINEL - FINAL INTEGRATION AUDIT")
print("=" * 65)

# 1. Frontend component verification

print("\n[1] FRONTEND COMPONENTS\n")

components = {
    "Security Dashboard": "dashboard",
    "Intrusion Detection": "detection",
    "Live Traffic Monitor": "multiclass-monitor",
    "Incident Management": "incident-management",
    "IoT Device Management": "devices",
    "Explainable AI": "explainability",
    "Incident Response Center": "response-center",
    "Reports and Batch Analysis": "batch-reports",
    "AI Security Assistant": "security-assistant",
}

component_root = ROOT / "frontend/src/app/components"

for name, directory in components.items():

    path = component_root / directory

    files = list(path.glob("*.ts"))

    check(
        name,
        path.is_dir() and bool(files),
        str(path.relative_to(ROOT)),
    )


# 2. Backend API verification

print("\n[2] BACKEND API VERIFICATION\n")

endpoints = {
    "Multiclass model": "/api/multiclass/model-info",
    "Device profiles": "/api/multiclass/device-profiles",
    "Incident management": "/api/multiclass/incidents/info",
    "Incident summary": "/api/multiclass/incidents/summary",
    "Incident listing": "/api/multiclass/incidents?limit=1",
    "Response policy": "/api/multiclass/response-policy",
    "Persistent response info": "/api/persistent-responses/info",
    "Persistent response listing": "/api/persistent-responses?limit=1",
}

for name, endpoint in endpoints.items():

    try:

        data = request(endpoint)

        check(name, isinstance(data, dict), endpoint)

    except Exception as error:

        check(name, False, error)


# 3. OpenAPI endpoint inventory

print("\n[3] REQUIRED API OPERATIONS\n")

required_operations = [
    ("/api/multiclass/predict", "post"),
    ("/api/multiclass/predict-batch", "post"),
    ("/api/multiclass/explain", "post"),
    ("/api/multiclass/assess-risk", "post"),
    ("/api/multiclass/compare-contexts", "post"),
    ("/api/multiclass/plan-response", "post"),
    ("/api/persistent-responses", "post"),
    ("/api/multiclass/incidents/{incident_id}/status", "patch"),
]

try:

    openapi = request("/openapi.json")

    paths = openapi["paths"]

    for path, method in required_operations:

        check(
            f"{method.upper()} {path}",
            method in paths.get(path, {}),
        )

    print(f"\nTotal API paths: {len(paths)}")

except Exception as error:

    check("OpenAPI inventory", False, error)


# 4. Model and dataset verification

print("\n[4] MODEL AND DATASET FILES\n")

required_files = [
    "models/random_forest_multiclass_calibrated.joblib",
    "data/processed/multiclass/verified/train.csv",
    "data/processed/multiclass/verified/validation.csv",
    "data/processed/multiclass/verified/test.csv",
    "results/multiclass/batch_test_datasets/seven_attack_samples.csv",
    "results/multiclass/batch_test_datasets/batch_test_100.csv",
    "results/multiclass/batch_test_datasets/batch_test_2500.csv",
    "frontend/public/test-samples/samples.json",
]

for filename in required_files:

    path = ROOT / filename

    exists = path.is_file()

    size = (
        f"{path.stat().st_size / 1024 / 1024:.2f} MB"
        if exists else "File missing"
    )

    check(filename, exists, size)


# 5. Response safety verification

print("\n[5] RESPONSE SAFETY\n")

try:

    info = request("/api/persistent-responses/info")

    safety_fields = {
        "simulation_only": True,
        "real_network_execution_enabled": False,
        "persistent_approval_enabled": False,
        "persistent_execution_enabled": False,
        "persistent_rollback_enabled": False,
    }

    for field, expected in safety_fields.items():

        actual = info.get(field)

        check(
            field,
            actual is expected,
            f"Expected={expected}, Actual={actual}",
        )

except Exception as error:

    check("Persistent response safety", False, error)


# 6. Dashboard legacy integration inspection

print("\n[6] LEGACY INTEGRATION INSPECTION\n")

dashboard = component_root / "dashboard/dashboard.html"

if dashboard.exists():

    template = dashboard.read_text(
        encoding="utf-8-sig"
    )

    legacy_selectors = [
        "app-csv-upload",
        "app-assistant-chat",
        "app-prediction-history",
        "app-prediction-trends",
    ]

    for selector in legacy_selectors:

        present = f"<{selector}" in template

        print(
            f"{'FOUND' if present else 'CLEAR'}: "
            f"{selector}"
        )

    print(
        "Migration notice present:",
        "migration-notice" in template,
    )

    print(
        "Multiclass reports registered:",
        "<app-batch-reports" in template,
    )

    print(
        "Multiclass assistant registered:",
        "<app-security-assistant" in template,
    )


# 7. Git status

print("\n[7] GIT STATUS\n")

for arguments in [
    ["git", "branch", "--show-current"],
    ["git", "status", "--short"],
]:

    result = subprocess.run(
        arguments,
        capture_output=True,
        text=True,
    )

    print(result.stdout or result.stderr)


# 8. Save final audit

passed = sum(item["passed"] for item in results)
failed = len(results) - passed

output = {
    "generated_at": datetime.now(
        timezone.utc
    ).isoformat(),
    "total_checks": len(results),
    "passed": passed,
    "failed": failed,
    "checks": results,
}

destination = (
    ROOT / "results/multiclass/final_integration"
)

destination.mkdir(
    parents=True,
    exist_ok=True,
)

report = destination / "integration_audit.json"

report.write_text(
    json.dumps(output, indent=2),
    encoding="utf-8",
)

print("\n" + "=" * 65)
print("FINAL INTEGRATION AUDIT SUMMARY")
print("=" * 65)
print(f"Total checks : {len(results)}")
print(f"Passed       : {passed}")
print(f"Failed       : {failed}")
print(f"Report       : {report}")
print("=" * 65)

if failed:
    raise SystemExit(1)
