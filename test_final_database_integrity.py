
from pathlib import Path
from datetime import datetime, timezone
import sys
import json

from sqlalchemy import text

ROOT = Path(__file__).resolve().parent

sys.path.insert(0, str(ROOT / "backend"))

from app.database import engine

SCHEMA = "multiclass"

TABLES = [
    "predictions",
    "risk_assessments",
    "incidents",
    "response_records",
    "response_audit_logs",
    "incident_audit_logs",
]

results = []


def check(name, passed, details=None):

    results.append({
        "check": name,
        "passed": bool(passed),
        "details": details,
    })

    status = "PASS" if passed else "FAIL"

    print(f"{status}: {name}")

    if details is not None:
        print(f"      {details}")


def scalar(connection, query):

    return connection.execute(
        text(query)
    ).scalar_one()


def zero_check(connection, name, query):

    count = scalar(connection, query)

    check(
        name,
        count == 0,
        {"violations": count},
    )


print("=" * 65)
print("IOT SENTINEL - DATABASE INTEGRITY TEST")
print("=" * 65)

with engine.connect() as connection:

    with connection.begin():

        connection.execute(text(
            "SET TRANSACTION ISOLATION LEVEL "
            "REPEATABLE READ, READ ONLY"
        ))

        # -------------------------------------------
        # 1. Database connectivity and table counts
        # -------------------------------------------

        print("\n[1] DATABASE TABLES\n")

        check(
            "Database connection",
            scalar(connection, "SELECT 1") == 1,
        )

        counts = {}

        for table in TABLES:

            count = scalar(
                connection,
                f"SELECT COUNT(*) FROM {SCHEMA}.{table}"
            )

            counts[table] = count

            check(
                f"Table accessible: {table}",
                True,
                {"records": count},
            )

        # -------------------------------------------
        # 2. Referential integrity
        # -------------------------------------------

        print("\n[2] REFERENTIAL INTEGRITY\n")

        relationships = [
            (
                "Risk assessments reference predictions",
                "risk_assessments",
                "prediction_id",
                "predictions",
            ),
            (
                "Incidents reference risk assessments",
                "incidents",
                "risk_assessment_id",
                "risk_assessments",
            ),
            (
                "Responses reference risk assessments",
                "response_records",
                "risk_assessment_id",
                "risk_assessments",
            ),
            (
                "Response audits reference responses",
                "response_audit_logs",
                "response_id",
                "response_records",
            ),
            (
                "Incident audits reference incidents",
                "incident_audit_logs",
                "incident_id",
                "incidents",
            ),
        ]

        for name, child, foreign_key, parent in relationships:

            zero_check(
                connection,
                name,
                f"""
                SELECT COUNT(*)
                FROM multiclass.{child} c
                LEFT JOIN multiclass.{parent} p
                    ON c.{foreign_key} = p.id
                WHERE p.id IS NULL
                """
            )

        # -------------------------------------------
        # 3. Risk and probability integrity
        # -------------------------------------------

        print("\n[3] RISK AND PROBABILITY INTEGRITY\n")

        zero_check(
            connection,
            "Valid risk score range",
            """
            SELECT COUNT(*)
            FROM multiclass.risk_assessments
            WHERE risk_score < 0
               OR risk_score > 100
               OR risk_score IS NULL
            """
        )

        zero_check(
            connection,
            "Valid risk level classification",
            """
            SELECT COUNT(*)
            FROM multiclass.risk_assessments
            WHERE risk_level IS DISTINCT FROM
                CASE
                    WHEN risk_score < 25 THEN 'low'
                    WHEN risk_score < 50 THEN 'medium'
                    WHEN risk_score < 75 THEN 'high'
                    ELSE 'critical'
                END
            """
        )

        zero_check(
            connection,
            "Valid calibrated attack probabilities",
            """
            SELECT COUNT(*)
            FROM multiclass.predictions
            WHERE calibrated_attack_probability < 0
               OR calibrated_attack_probability > 1
               OR calibrated_attack_probability IS NULL
            """
        )

        # -------------------------------------------
        # 4. Incident audit integrity
        # -------------------------------------------

        print("\n[4] INCIDENT AUDIT INTEGRITY\n")

        zero_check(
            connection,
            "Every incident has an audit history",
            """
            SELECT COUNT(*)
            FROM multiclass.incidents i
            WHERE NOT EXISTS (
                SELECT 1
                FROM multiclass.incident_audit_logs a
                WHERE a.incident_id = i.id
            )
            """
        )

        zero_check(
            connection,
            "Latest audit status matches incident status",
            """
            SELECT COUNT(*)
            FROM multiclass.incidents i
            LEFT JOIN LATERAL (
                SELECT new_status
                FROM multiclass.incident_audit_logs a
                WHERE a.incident_id = i.id
                ORDER BY event_sequence DESC
                LIMIT 1
            ) latest ON TRUE
            WHERE i.status IS DISTINCT FROM
                latest.new_status
            """
        )

        zero_check(
            connection,
            "Incident audit sequences are continuous",
            """
            SELECT COUNT(*)
            FROM (
                SELECT incident_id
                FROM multiclass.incident_audit_logs
                GROUP BY incident_id
                HAVING MIN(event_sequence) <> 1
                    OR MAX(event_sequence) <> COUNT(*)
                    OR COUNT(DISTINCT event_sequence)
                        <> COUNT(*)
            ) invalid
            """
        )

        zero_check(
            connection,
            "Incident audit transition chain is consistent",
            """
            WITH history AS (
                SELECT *,
                    LAG(new_status) OVER (
                        PARTITION BY incident_id
                        ORDER BY event_sequence
                    ) AS preceding_status
                FROM multiclass.incident_audit_logs
            )
            SELECT COUNT(*)
            FROM history
            WHERE previous_status IS DISTINCT FROM
                preceding_status
            """
        )

        zero_check(
            connection,
            "Incident registration events are valid",
            """
            SELECT COUNT(*)
            FROM multiclass.incident_audit_logs
            WHERE event_sequence = 1
              AND (
                  action <> 'incident_registered'
                  OR previous_status IS NOT NULL
                  OR new_status <> 'open'
              )
            """
        )

        # -------------------------------------------
        # 5. Response safety
        # -------------------------------------------

        print("\n[5] RESPONSE SAFETY\n")

        zero_check(
            connection,
            "No real network actions",
            """
            SELECT COUNT(*)
            FROM multiclass.response_records
            WHERE real_network_action_executed
                IS DISTINCT FROM FALSE
            """
        )

        zero_check(
            connection,
            "All responses remain simulation-only",
            """
            SELECT COUNT(*)
            FROM multiclass.response_records
            WHERE simulation_only
                IS DISTINCT FROM TRUE
            """
        )

        zero_check(
            connection,
            "No unauthorized persistent containment",
            """
            SELECT COUNT(*)
            FROM multiclass.response_records
            WHERE containment_authorized
               OR simulation_authorized
               OR approval_granted
               OR simulation_executed
               OR synthetic_fixture
            """
        )

        zero_check(
            connection,
            "Every response has audit history",
            """
            SELECT COUNT(*)
            FROM multiclass.response_records r
            WHERE NOT EXISTS (
                SELECT 1
                FROM multiclass.response_audit_logs a
                WHERE a.response_id = r.id
            )
            """
        )

        zero_check(
            connection,
            "Latest response audit matches current status",
            """
            SELECT COUNT(*)
            FROM multiclass.response_records r
            LEFT JOIN LATERAL (
                SELECT new_status
                FROM multiclass.response_audit_logs a
                WHERE a.response_id = r.id
                ORDER BY event_sequence DESC
                LIMIT 1
            ) latest ON TRUE
            WHERE r.status IS DISTINCT FROM
                latest.new_status
            """
        )

        # -------------------------------------------
        # 6. Row-level security
        # -------------------------------------------

        print("\n[6] DATABASE SECURITY CONFIGURATION\n")

        for table in TABLES:

            enabled = connection.execute(
                text("""
                    SELECT c.relrowsecurity
                    FROM pg_class c
                    JOIN pg_namespace n
                        ON n.oid = c.relnamespace
                    WHERE n.nspname = :schema
                      AND c.relname = :table
                """),
                {
                    "schema": SCHEMA,
                    "table": table,
                },
            ).scalar_one()

            check(
                f"Row-level security enabled: {table}",
                enabled is True,
            )


# -------------------------------------------
# 7. Save verification results
# -------------------------------------------

passed = sum(item["passed"] for item in results)
failed = len(results) - passed

output = {
    "generated_at": datetime.now(
        timezone.utc
    ).isoformat(),
    "schema": SCHEMA,
    "read_only_verification": True,
    "table_counts": counts,
    "total_checks": len(results),
    "passed": passed,
    "failed": failed,
    "checks": results,
}

destination = (
    ROOT / "results/multiclass/final_database_integrity"
)

destination.mkdir(
    parents=True,
    exist_ok=True,
)

report = destination / "verification_results.json"

report.write_text(
    json.dumps(output, indent=2),
    encoding="utf-8",
)

print("\n" + "=" * 65)
print("DATABASE INTEGRITY SUMMARY")
print("=" * 65)
print(f"Total checks: {len(results)}")
print(f"Passed      : {passed}")
print(f"Failed      : {failed}")
print(f"Report      : {report}")
print("=" * 65)

if failed:
    raise SystemExit(1)
