from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.exc import DBAPIError

from backend.app.database import engine

from backend.app.incident_management_service import (
    IncidentStateError,
    retrieve_incidents,
    retrieve_incident,
    retrieve_incident_summary,
    retrieve_incident_audit,
    get_incident_management_info,
    change_status_in_transaction,
    validate_status_transition,
)

from backend.app.incident_repository import (
    get_incident,
    get_incident_audit_logs,
)


def expect_error(
    function,
    exception_type,
    test_name,
):

    try:

        function()

    except exception_type:

        print(f"{test_name}: PASSED")

    else:

        raise AssertionError(
            f"{test_name}: Expected exception."
        )


def expect_database_rejection(
    connection,
    statement,
    parameters,
    test_name,
    expected_message=None,
):

    try:

        with connection.begin_nested():

            connection.execute(
                text(statement),
                parameters,
            )

    except DBAPIError as error:

        if expected_message is not None:

            assert expected_message in str(error.orig)

        print(f"{test_name}: PASSED")

    else:

        raise AssertionError(
            f"{test_name}: Database accepted "
            "an invalid operation."
        )


def main():

    print("=" * 75)
    print("INCIDENT MANAGEMENT SERVICE TEST")
    print("=" * 75)

    # 1. Verify service information.

    info = get_incident_management_info()

    assert info["persistent_storage"]
    assert info["transactional_status_updates"]
    assert info["simulation_only"]
    assert not info["real_network_execution_enabled"]

    print("\nService information: PASSED")

    # 2. Verify incident summary.

    summary = retrieve_incident_summary()

    assert summary["total_incidents"] == 6
    assert summary["open_incidents"] == 6
    assert summary["critical_incidents"] == 4
    assert summary["high_incidents"] == 2
    assert summary["active_incidents"] == 6

    print("\nINCIDENT SUMMARY")

    for key, value in summary.items():
        print(f"{key}: {value}")

    print("Incident summary: PASSED")

    # 3. Verify listing and filtering.

    listing = retrieve_incidents(limit=100)

    assert listing["total"] == 6
    assert listing["returned"] == 6

    print("\nIncident listing: PASSED")

    critical = retrieve_incidents(
        severity="critical"
    )

    assert critical["total"] == 4

    high = retrieve_incidents(
        severity="high"
    )

    assert high["total"] == 2

    mirai = retrieve_incidents(
        predicted_family="Mirai"
    )

    assert mirai["total"] == 6

    open_incidents = retrieve_incidents(
        status="open"
    )

    assert open_incidents["total"] == 6

    print("Incident filtering: PASSED")

    page_ids = []

    for offset in range(6):

        page = retrieve_incidents(
            limit=1,
            offset=offset,
        )

        assert page["returned"] == 1

        page_ids.append(
            page["incidents"][0]["incident_id"]
        )

    assert len(set(page_ids)) == 6

    print("Pagination: PASSED")

    # 4. Select two incidents for lifecycle tests.

    incident_ids = [
        record["incident_id"]
        for record in listing["incidents"][:2]
    ]

    original_records = {
        incident_id:
            retrieve_incident(incident_id)

        for incident_id in incident_ids
    }

    original_audits = {
        incident_id:
            retrieve_incident_audit(incident_id)

        for incident_id in incident_ids
    }

    for incident_id in incident_ids:

        assert (
            original_records[incident_id]["status"]
            == "open"
        )

        assert (
            original_audits[incident_id]["total_events"]
            == 1
        )

    print("Incident detail retrieval: PASSED")
    print("Audit history retrieval: PASSED")

    # 5. Validate invalid service inputs.

    expect_error(
        lambda: retrieve_incidents(limit=0),
        ValueError,
        "Invalid pagination limit",
    )

    expect_error(
        lambda: retrieve_incidents(offset=-1),
        ValueError,
        "Invalid pagination offset",
    )

    expect_error(
        lambda: retrieve_incidents(
            severity="invalid"
        ),
        ValueError,
        "Invalid severity",
    )

    expect_error(
        lambda: retrieve_incident("invalid-uuid"),
        ValueError,
        "Invalid incident UUID",
    )

    expect_error(
        lambda: retrieve_incident(str(uuid4())),
        KeyError,
        "Unknown incident",
    )

    # 6. Verify all lifecycle combinations.

    allowed = {
        ("open", "acknowledged"),
        ("acknowledged", "investigating"),
        ("investigating", "resolved"),
        ("investigating", "false_positive"),
    }

    statuses = [
        "open",
        "acknowledged",
        "investigating",
        "resolved",
        "false_positive",
    ]

    for old_status in statuses:

        for new_status in statuses:

            if (old_status, new_status) in allowed:

                assert validate_status_transition(
                    old_status,
                    new_status,
                )

            else:

                try:

                    validate_status_transition(
                        old_status,
                        new_status,
                    )

                except IncidentStateError:
                    pass

                else:

                    raise AssertionError(
                        "Invalid transition accepted."
                    )

    print("\nAll 25 lifecycle combinations: PASSED")

    # 7. Transactional lifecycle testing.

    print("\nTRANSACTIONAL LIFECYCLE TESTS")

    with engine.connect() as connection:

        transaction = connection.begin()

        try:

            for incident_id, final_status in zip(
                incident_ids,
                ("resolved", "false_positive"),
            ):

                print(
                    "\nTesting terminal state:",
                    final_status,
                )

                for sequence, new_status in enumerate(
                    (
                        "acknowledged",
                        "investigating",
                        final_status,
                    ),
                    start=2,
                ):

                    result = (
                        change_status_in_transaction(
                            connection=connection,
                            incident_id=incident_id,
                            new_status=new_status,
                            actor_name="test_analyst",
                            reason=(
                                "Rollback-only "
                                "integration test."
                            ),
                        )
                    )

                    assert (
                        result["incident"]["status"]
                        == new_status
                    )

                    assert (
                        result["audit_event"]
                        ["event_sequence"]
                        == sequence
                    )

                    assert not (
                        result["audit_event"]
                        ["actor_authenticated"]
                    )

                    assert not (
                        result[
                            "real_network_action_executed"
                        ]
                    )

                    assert not (
                        result["containment_authorized"]
                    )

                    print(
                        result["previous_status"],
                        "->",
                        new_status,
                        "| PASSED",
                    )

                incident = get_incident(
                    connection,
                    incident_id,
                )

                audit_logs = get_incident_audit_logs(
                    connection,
                    incident_id,
                )

                assert incident["resolved_at"] is not None

                assert len(audit_logs) == 4

                assert [
                    event["event_sequence"]
                    for event in audit_logs
                ] == [1, 2, 3, 4]

                expect_error(
                    lambda: change_status_in_transaction(
                        connection=connection,
                        incident_id=incident_id,
                        new_status="open",
                        actor_name="test_analyst",
                        reason="Invalid reopening.",
                    ),
                    IncidentStateError,
                    "Terminal state protection",
                )

                print("Audit sequence: PASSED")

            # 8. Test append-only protections.

            parameters = {
                "incident_id": incident_ids[0]
            }

            expect_database_rejection(
                connection,
                """
                    UPDATE multiclass.incident_audit_logs
                    SET reason = 'Modified'
                    WHERE incident_id =
                        CAST(:incident_id AS UUID)
                """,
                parameters,
                "Audit UPDATE protection",
                "Incident audit history is append-only",
            )

            expect_database_rejection(
                connection,
                """
                    DELETE FROM
                        multiclass.incident_audit_logs
                    WHERE incident_id =
                        CAST(:incident_id AS UUID)
                """,
                parameters,
                "Audit DELETE protection",
                "Incident audit history is append-only",
            )

        finally:

            transaction.rollback()

            print("\nTest transaction rolled back.")

    # 9. Verify original records were preserved.

    for incident_id in incident_ids:

        assert (
            retrieve_incident(incident_id)
            == original_records[incident_id]
        )

        assert (
            retrieve_incident_audit(incident_id)
            == original_audits[incident_id]
        )

    final_summary = retrieve_incident_summary()

    assert final_summary == summary

    print("Rollback verification: PASSED")
    print("Original records preserved: PASSED")

    with engine.connect() as connection:

        audit_count = connection.execute(
            text("""
                SELECT COUNT(*)
                FROM multiclass.incident_audit_logs
            """)
        ).scalar_one()

        assert audit_count == 6

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

    print("\n" + "=" * 75)
    print("ALL INCIDENT MANAGEMENT TESTS PASSED")
    print("=" * 75)

    print("Lifecycle combinations tested: 25")
    print("Terminal states tested: 2")
    print("Temporary status updates: 6")
    print("Temporary audit events: 6")
    print("Permanent incident modifications: 0")
    print("Permanent audit records added: 0")
    print("Existing incident audit records: 6")
    print("Actual network actions: 0")


if __name__ == "__main__":
    main()
