from pathlib import Path
import sys
import json

from sqlalchemy import text


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))

from backend.app.database import engine


EXPECTED_TABLES = {
    "predictions",
    "risk_assessments",
    "incidents",
    "response_records",
    "response_audit_logs",
}


EXPECTED_LEGACY_TABLES = {
    "user_profiles",
    "devices",
    "predictions",
    "incidents",
    "incident_audit_logs",
}


OUTPUT_DIR = (
    ROOT
    / "results"
    / "multiclass"
    / "database_migration"
)


def main():

    print("=" * 80)
    print("MULTICLASS DATABASE MIGRATION VERIFICATION")
    print("=" * 80)

    with engine.connect() as connection:

        connection.execute(
            text("SET TRANSACTION READ ONLY")
        )

        connection.execute(
            text("SET LOCAL statement_timeout = '30s'")
        )

        connection.execute(text("SELECT 1"))

        print("\nDatabase connection: PASSED")

        schema_exists = connection.execute(
            text("""
                SELECT EXISTS (
                    SELECT 1
                    FROM pg_namespace
                    WHERE nspname = 'multiclass'
                )
            """)
        ).scalar_one()

        assert schema_exists, (
            "Multiclass schema does not exist."
        )

        print("Multiclass schema: PASSED")

        query = text("""
            SELECT
                c.relname AS table_name,

                c.relrowsecurity AS rls_enabled,

                has_table_privilege(
                    current_user,
                    c.oid,
                    'SELECT'
                ) AS can_select,

                has_table_privilege(
                    current_user,
                    c.oid,
                    'INSERT'
                ) AS can_insert,

                has_table_privilege(
                    current_user,
                    c.oid,
                    'UPDATE'
                ) AS can_update

            FROM pg_class c

            JOIN pg_namespace n
                ON n.oid = c.relnamespace

            WHERE n.nspname = 'multiclass'
              AND c.relkind = 'r'

            ORDER BY c.relname
        """)

        rows = [
            dict(row)
            for row in connection.execute(
                query
            ).mappings()
        ]

        actual_tables = {
            row["table_name"]
            for row in rows
        }

        missing_tables = (
            EXPECTED_TABLES - actual_tables
        )

        assert not missing_tables, (
            f"Missing tables: {missing_tables}"
        )

        print("\nMULTICLASS TABLES")

        for row in rows:

            print(
                f'{row["table_name"]:25}'
                f'RLS: {str(row["rls_enabled"]):6}'
                f'SELECT: {str(row["can_select"]):6}'
                f'INSERT: {str(row["can_insert"]):6}'
                f'UPDATE: {row["can_update"]}'
            )

            assert row["rls_enabled"], (
                f'RLS disabled: {row["table_name"]}'
            )

        # Check schema access and RLS behavior.

        access = dict(
            connection.execute(
                text("""
                    SELECT
                        has_schema_privilege(
                            current_user,
                            'multiclass',
                            'USAGE'
                        ) AS schema_usage,

                        row_security_active(
                            'multiclass.predictions'::regclass
                        ) AS prediction_rls_active,

                        row_security_active(
                            'multiclass.response_records'::regclass
                        ) AS response_rls_active
                """)
            ).mappings().one()
        )

        print("\nBACKEND ACCESS")

        for key, value in access.items():
            print(f"{key}: {value}")

        # Verify legacy tables still exist.

        legacy_tables = set(
            connection.execute(
                text("""
                    SELECT c.relname
                    FROM pg_class c
                    JOIN pg_namespace n
                        ON n.oid = c.relnamespace
                    WHERE n.nspname = 'public'
                      AND c.relkind = 'r'
                """)
            ).scalars().all()
        )

        missing_legacy = (
            EXPECTED_LEGACY_TABLES - legacy_tables
        )

        assert not missing_legacy, (
            f"Missing legacy tables: {missing_legacy}"
        )

        print("\nLEGACY TABLES")

        for table in sorted(
            EXPECTED_LEGACY_TABLES
        ):
            print(f"{table}: PRESERVED")

        # Verify constraints.

        constraint_query = text("""
            SELECT
                c.relname AS table_name,
                con.conname AS constraint_name,
                pg_get_constraintdef(
                    con.oid
                ) AS definition

            FROM pg_constraint con

            JOIN pg_class c
                ON c.oid = con.conrelid

            JOIN pg_namespace n
                ON n.oid = c.relnamespace

            WHERE n.nspname = 'multiclass'

            ORDER BY c.relname, con.conname
        """)

        constraints = [
            dict(row)
            for row in connection.execute(
                constraint_query
            ).mappings()
        ]

        constraint_names = {
            row["constraint_name"]
            for row in constraints
        }

        required_constraints = {
            "mc_prediction_label_check",
            "mc_prediction_family_check",
            "mc_risk_score_check",
            "mc_response_no_real_execution_check",
            "mc_response_no_containment_check",
            "mc_response_fixture_safety_check",
            "mc_response_execution_check",
            "mc_audit_sequence_unique",
        }

        assert required_constraints.issubset(
            constraint_names
        ), "Required constraints are missing."

        print("\nRequired constraints: PASSED")

        # Check direct client privileges.

        client_access = [
            dict(row)
            for row in connection.execute(
                text("""
                    SELECT
                        rolname,
                        has_schema_privilege(
                            rolname,
                            'multiclass',
                            'USAGE'
                        ) AS schema_usage
                    FROM pg_roles
                    WHERE rolname IN (
                        'anon',
                        'authenticated'
                    )
                """)
            ).mappings()
        ]

        print("\nDIRECT CLIENT ACCESS")

        for row in client_access:

            print(row)

            assert not row["schema_usage"], (
                "Unexpected direct client access."
            )

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    report = {
        "schema": "multiclass",
        "tables": rows,
        "legacy_tables": sorted(legacy_tables),
        "constraints": constraints,
        "backend_access": access,
        "client_access": client_access,
    }

    output_path = (
        OUTPUT_DIR
        / "migration_verification.json"
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

    print("\n" + "=" * 80)
    print("DATABASE STRUCTURE VERIFICATION PASSED")
    print("=" * 80)

    print("Multiclass tables:", len(rows))
    print("Legacy tables preserved:", len(EXPECTED_LEGACY_TABLES))
    print("Constraints found:", len(constraints))

    print("Report saved to:", output_path)

    backend_permissions = (
        access["schema_usage"]
        and all(
            row["can_select"]
            and row["can_insert"]
            for row in rows
        )
        and all(
            row["can_update"]
            for row in rows
            if row["table_name"] in (
                "incidents",
                "response_records"
            )
        )
    )

    if not backend_permissions:

        print(
            "WARNING: Backend database privileges "
            "require configuration."
        )

    if (
        access["prediction_rls_active"]
        or access["response_rls_active"]
    ):

        print(
            "WARNING: Backend is subject to RLS. "
            "Access policies must be reviewed."
        )

    print("No database records were modified.")
    print("Write operations have not yet been tested.")


if __name__ == "__main__":
    main()
