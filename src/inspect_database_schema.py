from pathlib import Path
import sys
import json
from datetime import datetime, timezone

from sqlalchemy import inspect, text


ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))

from backend.app.database import engine


OUTPUT_DIR = (
    ROOT
    / "results"
    / "multiclass"
    / "database_inspection"
)


def main():

    print("=" * 80)
    print("SUPABASE DATABASE SCHEMA INSPECTION")
    print("=" * 80)

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    schema_report = {
        "inspection_time": datetime.now(
            timezone.utc
        ).isoformat(),

        "database_type": "PostgreSQL",

        "schema": "public",

        "tables": [],
    }

    with engine.connect() as connection:

        # Read-only inspection

        connection.execute(
            text("SET TRANSACTION READ ONLY")
        )

        connection.execute(
            text("SET LOCAL statement_timeout = '30s'")
        )

        connection.execute(text("SELECT 1"))

        print("\nDatabase connection: SUCCESSFUL")

        inspector = inspect(connection)

        tables = inspector.get_table_names(
            schema="public"
        )

        print("\nTotal public tables:", len(tables))

        for table in tables:

            print("\n" + "=" * 80)
            print("TABLE:", table)
            print("=" * 80)

            columns = inspector.get_columns(
                table,
                schema="public",
            )

            primary_key = inspector.get_pk_constraint(
                table,
                schema="public",
            )

            foreign_keys = inspector.get_foreign_keys(
                table,
                schema="public",
            )

            unique_constraints = (
                inspector.get_unique_constraints(
                    table,
                    schema="public",
                )
            )

            check_constraints = (
                inspector.get_check_constraints(
                    table,
                    schema="public",
                )
            )

            indexes = inspector.get_indexes(
                table,
                schema="public",
            )

            table_info = {
                "table_name": table,
                "columns": [],
                "primary_key": primary_key,
                "foreign_keys": foreign_keys,
                "unique_constraints": unique_constraints,
                "check_constraints": check_constraints,
                "indexes": indexes,
            }

            print("\nCOLUMNS")

            for column in columns:

                column_info = {
                    "name": column["name"],

                    "type": str(column["type"]),

                    "nullable": column["nullable"],

                    "default": column.get("default"),

                    "identity": column.get("identity"),

                    "computed": column.get("computed"),
                }

                table_info["columns"].append(
                    column_info
                )

                print(
                    f'{column_info["name"]:30}'
                    f'{column_info["type"]:25}'
                    f'Nullable: {column_info["nullable"]}'
                )

            print("\nPRIMARY KEY")
            print(primary_key)

            print("\nFOREIGN KEYS")

            for foreign_key in foreign_keys:
                print(foreign_key)

            print("\nUNIQUE CONSTRAINTS")

            for constraint in unique_constraints:
                print(constraint)

            print("\nCHECK CONSTRAINTS")

            for constraint in check_constraints:
                print(constraint)

            print("\nINDEXES")

            for index in indexes:
                print(index)

            schema_report["tables"].append(
                table_info
            )

        # Row-level security configuration

        print("\n" + "=" * 80)
        print("ROW LEVEL SECURITY")
        print("=" * 80)

        rls_query = text("""
            SELECT
                c.relname AS table_name,
                c.relrowsecurity AS rls_enabled,
                c.relforcerowsecurity AS rls_forced
            FROM pg_class c
            JOIN pg_namespace n
                ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND c.relkind IN ('r', 'p')
            ORDER BY c.relname
        """)

        rls_rows = [
            dict(row)
            for row in connection.execute(
                rls_query
            ).mappings()
        ]

        schema_report["row_level_security"] = (
            rls_rows
        )

        for row in rls_rows:

            print(
                f'{row["table_name"]:30}'
                f'RLS: {row["rls_enabled"]}'
                f' | Forced: {row["rls_forced"]}'
            )

        # Inspect existing RLS policies

        policy_query = text("""
            SELECT
                tablename,
                policyname,
                permissive,
                roles,
                cmd,
                qual,
                with_check
            FROM pg_policies
            WHERE schemaname = 'public'
            ORDER BY tablename, policyname
        """)

        policies = [
            dict(row)
            for row in connection.execute(
                policy_query
            ).mappings()
        ]

        schema_report["rls_policies"] = policies

        print("\nRLS POLICIES")

        for policy in policies:
            print(policy)

        # Inspect existing triggers

        trigger_query = text("""
            SELECT
                c.relname AS table_name,
                t.tgname AS trigger_name,
                pg_get_triggerdef(t.oid) AS definition
            FROM pg_trigger t
            JOIN pg_class c
                ON c.oid = t.tgrelid
            JOIN pg_namespace n
                ON n.oid = c.relnamespace
            WHERE n.nspname = 'public'
              AND NOT t.tgisinternal
            ORDER BY c.relname, t.tgname
        """)

        triggers = [
            dict(row)
            for row in connection.execute(
                trigger_query
            ).mappings()
        ]

        schema_report["triggers"] = triggers

        print("\nDATABASE TRIGGERS")

        for trigger in triggers:
            print(trigger)

    output_path = (
        OUTPUT_DIR / "database_schema.json"
    )

    with open(
        output_path,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            schema_report,
            file,
            indent=4,
            default=str,
        )

    print("\n" + "=" * 80)
    print("DATABASE INSPECTION COMPLETED")
    print("=" * 80)

    print("Tables inspected:", len(tables))
    print("RLS policies:", len(policies))
    print("Triggers:", len(triggers))

    print("Schema report:", output_path)

    print("No database records were modified.")
    print("No database tables were created or deleted.")


if __name__ == "__main__":
    main()
