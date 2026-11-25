from pathlib import Path
import json
import sys

from sqlalchemy import text


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))

from backend.app.database import engine


OUTPUT_DIR = (
    ROOT
    / "results"
    / "multiclass"
    / "incident_management"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True,
)


def inspect_database():

    report = {}

    with engine.connect() as connection:

        connection.execute(
            text("SET TRANSACTION READ ONLY")
        )

        print("=" * 75)
        print("MULTICLASS INCIDENT DATABASE INSPECTION")
        print("=" * 75)

        # 1. Inspect existing tables

        tables = connection.execute(
            text("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'multiclass'
                ORDER BY table_name
            """)
        ).scalars().all()

        report["tables"] = list(tables)

        print("\nEXISTING MULTICLASS TABLES")

        for table in tables:
            print(table)

        # 2. Inspect incident-related columns

        columns = connection.execute(
            text("""
                SELECT
                    table_name,
                    column_name,
                    data_type,
                    is_nullable,
                    column_default
                FROM information_schema.columns
                WHERE table_schema = 'multiclass'
                AND table_name IN (
                    'incidents',
                    'incident_audit_logs',
                    'response_audit_logs'
                )
                ORDER BY
                    table_name,
                    ordinal_position
            """)
        ).mappings().all()

        report["columns"] = [
            dict(row) for row in columns
        ]

        print("\nINCIDENT TABLE STRUCTURE")

        for row in columns:

            print(
                f"{row['table_name']}."
                f"{row['column_name']} | "
                f"{row['data_type']} | "
                f"Nullable: {row['is_nullable']}"
            )

        # 3. Inspect incident distribution

        distribution = connection.execute(
            text("""
                SELECT
                    status,
                    severity,
                    COUNT(*) AS total_incidents
                FROM multiclass.incidents
                GROUP BY status, severity
                ORDER BY status, severity
            """)
        ).mappings().all()

        report["incident_distribution"] = [
            dict(row) for row in distribution
        ]

        print("\nINCIDENT DISTRIBUTION")

        for row in distribution:

            print(
                f"Status: {row['status']} | "
                f"Severity: {row['severity']} | "
                f"Count: {row['total_incidents']}"
            )

        # 4. Inspect database constraints

        constraints = connection.execute(
            text("""
                SELECT
                    conname AS constraint_name,
                    pg_get_constraintdef(oid)
                        AS definition
                FROM pg_constraint
                WHERE conrelid =
                    'multiclass.incidents'::regclass
                ORDER BY conname
            """)
        ).mappings().all()

        report["constraints"] = [
            dict(row) for row in constraints
        ]

        print("\nINCIDENT CONSTRAINTS")

        for row in constraints:

            print(
                row["constraint_name"],
                "->",
                row["definition"],
            )

        # 5. Verify audit table availability

        audit_table_exists = (
            "incident_audit_logs" in tables
        )

        report["incident_audit_table_exists"] = (
            audit_table_exists
        )

        print("\nINCIDENT AUDIT TABLE EXISTS:")
        print(audit_table_exists)

        # 6. Count existing records

        counts = connection.execute(
            text("""
                SELECT
                    (SELECT COUNT(*)
                     FROM multiclass.predictions)
                        AS predictions,

                    (SELECT COUNT(*)
                     FROM multiclass.risk_assessments)
                        AS risk_assessments,

                    (SELECT COUNT(*)
                     FROM multiclass.incidents)
                        AS incidents,

                    (SELECT COUNT(*)
                     FROM multiclass.response_records)
                        AS response_records,

                    (SELECT COUNT(*)
                     FROM multiclass.response_audit_logs)
                        AS response_audit_logs
            """)
        ).mappings().one()

        report["record_counts"] = dict(counts)

        print("\nDATABASE RECORD COUNTS")

        for name, count in counts.items():
            print(f"{name}: {count}")

    output_path = (
        OUTPUT_DIR
        / "incident_database_inspection.json"
    )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            report,
            file,
            indent=4,
            default=str,
        )

    print("\n" + "=" * 75)
    print("DATABASE INSPECTION COMPLETED SUCCESSFULLY")
    print("=" * 75)

    print("Database records modified: 0")
    print("Report saved to:", output_path)


if __name__ == "__main__":
    inspect_database()
