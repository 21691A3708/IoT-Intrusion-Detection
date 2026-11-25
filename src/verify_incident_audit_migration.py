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


def verify_migration():

    report = {}

    print("=" * 75)
    print("INCIDENT AUDIT MIGRATION VERIFICATION")
    print("=" * 75)

    with engine.connect() as connection:

        connection.execute(
            text("SET TRANSACTION READ ONLY")
        )

        # 1. Verify table availability

        tables = connection.execute(
            text("""
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = 'multiclass'
                ORDER BY table_name
            """)
        ).scalars().all()

        expected_tables = {
            "predictions",
            "risk_assessments",
            "incidents",
            "response_records",
            "response_audit_logs",
            "incident_audit_logs",
        }

        assert expected_tables.issubset(set(tables))

        report["tables"] = list(tables)

        print("\nTABLE VERIFICATION")

        for table in tables:
            print(f"{table}: AVAILABLE")

        print("Required tables: PASSED")

        # 2. Verify backend database permissions

        permissions = connection.execute(
            text("""
                SELECT
                    has_schema_privilege(
                        current_user,
                        'multiclass',
                        'USAGE'
                    ) AS schema_usage,

                    has_table_privilege(
                        current_user,
                        'multiclass.incident_audit_logs',
                        'SELECT'
                    ) AS can_select,

                    has_table_privilege(
                        current_user,
                        'multiclass.incident_audit_logs',
                        'INSERT'
                    ) AS can_insert,

                    has_table_privilege(
                        current_user,
                        'multiclass.incidents',
                        'UPDATE'
                    ) AS can_update_incidents,

                    row_security_active(
                        'multiclass.incident_audit_logs'
                        ::regclass
                    ) AS rls_active
            """)
        ).mappings().one()

        report["permissions"] = dict(permissions)

        print("\nBACKEND DATABASE PERMISSIONS")

        for key, value in permissions.items():
            print(f"{key}: {value}")

        assert permissions["schema_usage"]
        assert permissions["can_select"]
        assert permissions["can_insert"]
        assert permissions["can_update_incidents"]

        print("Backend permissions: PASSED")

        # 3. Verify audit table constraints

        constraints = connection.execute(
            text("""
                SELECT
                    conname AS constraint_name,
                    pg_get_constraintdef(oid)
                        AS definition
                FROM pg_constraint
                WHERE conrelid =
                    'multiclass.incident_audit_logs'
                    ::regclass
                ORDER BY conname
            """)
        ).mappings().all()

        report["constraints"] = [
            dict(row) for row in constraints
        ]

        constraint_names = {
            row["constraint_name"]
            for row in constraints
        }

        required_constraints = {
            "mc_incident_audit_sequence_unique",
            "mc_incident_audit_sequence_check",
            "mc_incident_audit_actor_check",
            "mc_incident_audit_auth_check",
            "mc_incident_audit_action_check",
            "mc_incident_audit_previous_status_check",
            "mc_incident_audit_new_status_check",
            "mc_incident_audit_transition_check",
            "mc_incident_audit_reason_check",
            "mc_incident_audit_details_check",
            "mc_incident_audit_simulation_check",
        }

        assert required_constraints.issubset(
            constraint_names
        )

        print("\nAUDIT CONSTRAINTS")

        for row in constraints:
            print(row["constraint_name"])

        print("Total constraints:", len(constraints))
        print("Required constraints: PASSED")

        # 4. Verify append-only triggers

        triggers = connection.execute(
            text("""
                SELECT
                    tgname AS trigger_name,
                    tgenabled AS enabled,
                    pg_get_triggerdef(oid)
                        AS definition
                FROM pg_trigger
                WHERE tgrelid =
                    'multiclass.incident_audit_logs'
                    ::regclass
                AND NOT tgisinternal
                ORDER BY tgname
            """)
        ).mappings().all()

        report["triggers"] = [
            dict(row) for row in triggers
        ]

        enabled_triggers = {
            row["trigger_name"]
            for row in triggers
            if row["enabled"] in ("O", "A")
        }

        assert (
            "trg_mc_incident_audit_immutable"
            in enabled_triggers
        )

        assert (
            "trg_mc_incident_audit_no_truncate"
            in enabled_triggers
        )

        print("\nAPPEND-ONLY TRIGGERS")

        for row in triggers:
            print(
                row["trigger_name"],
                "| Enabled:",
                row["enabled"],
            )

        print("Trigger configuration: PASSED")

        # 5. Verify row-level security

        security = connection.execute(
            text("""
                SELECT
                    relrowsecurity AS rls_enabled,
                    relforcerowsecurity AS rls_forced
                FROM pg_class
                WHERE oid =
                    'multiclass.incident_audit_logs'
                    ::regclass
            """)
        ).mappings().one()

        report["security"] = dict(security)

        assert security["rls_enabled"]

        print("\nROW LEVEL SECURITY")

        for key, value in security.items():
            print(f"{key}: {value}")

        print("RLS configuration: PASSED")

        # 6. Verify frontend role restrictions

        frontend_permissions = connection.execute(
            text("""
                SELECT
                    has_schema_privilege(
                        'anon',
                        'multiclass',
                        'USAGE'
                    ) AS anon_schema_usage,

                    has_schema_privilege(
                        'authenticated',
                        'multiclass',
                        'USAGE'
                    ) AS authenticated_schema_usage,

                    has_table_privilege(
                        'anon',
                        'multiclass.incident_audit_logs',
                        'SELECT'
                    ) AS anon_select,

                    has_table_privilege(
                        'authenticated',
                        'multiclass.incident_audit_logs',
                        'SELECT'
                    ) AS authenticated_select,

                    has_table_privilege(
                        'anon',
                        'multiclass.incident_audit_logs',
                        'INSERT'
                    ) AS anon_insert,

                    has_table_privilege(
                        'authenticated',
                        'multiclass.incident_audit_logs',
                        'INSERT'
                    ) AS authenticated_insert
            """)
        ).mappings().one()

        report["frontend_permissions"] = dict(
            frontend_permissions
        )

        print("\nFRONTEND ROLE RESTRICTIONS")

        for key, value in frontend_permissions.items():
            print(f"{key}: {value}")

        assert not any(frontend_permissions.values())

        print("Frontend restrictions: PASSED")

        # 7. Verify initial incident registration

        audit_records = connection.execute(
            text("""
                SELECT
                    a.incident_id,
                    a.event_sequence,
                    a.actor_name,
                    a.actor_authenticated,
                    a.action,
                    a.previous_status,
                    a.new_status,
                    a.reason,
                    a.simulation_only,
                    a.details,
                    i.status AS incident_status,
                    i.severity
                FROM multiclass.incident_audit_logs a
                JOIN multiclass.incidents i
                    ON i.id = a.incident_id
                ORDER BY
                    a.incident_id,
                    a.event_sequence
            """)
        ).mappings().all()

        report["audit_records"] = [
            dict(row) for row in audit_records
        ]

        print("\nINITIAL INCIDENT AUDIT RECORDS")

        for row in audit_records:

            assert row["event_sequence"] == 1
            assert row["actor_name"] == "system"
            assert not row["actor_authenticated"]

            assert row["action"] == (
                "incident_registered"
            )

            assert row["previous_status"] is None

            assert row["new_status"] == (
                row["incident_status"]
            )

            assert row["simulation_only"]

            assert row["details"].get(
                "migration_backfill"
            ) is True

            print(
                row["incident_id"],
                "|",
                row["severity"],
                "|",
                row["new_status"],
                "| PASSED",
            )

        # 8. Verify database record counts

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
                        AS response_audit_logs,

                    (SELECT COUNT(*)
                     FROM multiclass.incident_audit_logs)
                        AS incident_audit_logs
            """)
        ).mappings().one()

        report["record_counts"] = dict(counts)

        print("\nDATABASE RECORD COUNTS")

        for key, value in counts.items():
            print(f"{key}: {value}")

        assert counts["incidents"] == 6
        assert counts["incident_audit_logs"] == 6

        assert len({
            row["incident_id"]
            for row in audit_records
        }) == counts["incidents"]

        expected_counts = {
            "predictions": 7,
            "risk_assessments": 7,
            "incidents": 6,
            "response_records": 7,
            "response_audit_logs": 7,
            "incident_audit_logs": 6,
        }

        assert dict(counts) == expected_counts

        print("Record preservation: PASSED")

        # 9. Verify existing response safety

        unsafe_responses = connection.execute(
            text("""
                SELECT COUNT(*)
                FROM multiclass.response_records
                WHERE real_network_action_executed
                    = TRUE
                OR containment_authorized = TRUE
                OR simulation_only = FALSE
            """)
        ).scalar_one()

        assert unsafe_responses == 0

        report["unsafe_responses"] = unsafe_responses

        print("\nRESPONSE SAFETY VERIFICATION")
        print("Unsafe responses:", unsafe_responses)
        print("Safety restrictions: PASSED")

    report["verification_status"] = "PASSED"

    output_path = (
        OUTPUT_DIR
        / "incident_audit_migration_verification.json"
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
    print("ALL INCIDENT AUDIT MIGRATION CHECKS PASSED")
    print("=" * 75)

    print("Incident audit records: 6")
    print("Total database records: 40")
    print("Database records modified: 0")
    print("Actual network actions: 0")
    print("Report saved to:", output_path)


if __name__ == "__main__":
    verify_migration()
