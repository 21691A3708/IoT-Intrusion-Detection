from uuid import uuid4

import requests


BASE_URL = (
    "http://127.0.0.1:8000"
    "/api/multiclass/incidents"
)

TIMEOUT = 30


def get(endpoint="", params=None):

    response = requests.get(
        BASE_URL + endpoint,
        params=params,
        timeout=TIMEOUT,
    )

    assert response.status_code == 200, (
        response.status_code,
        response.text,
    )

    return response.json()


def expect_status(
    response,
    expected,
    test_name,
):

    assert response.status_code == expected, (
        test_name,
        response.status_code,
        response.text,
    )

    print(
        f"{test_name}: PASSED "
        f"({expected})"
    )


def main():

    print("=" * 75)
    print("INCIDENT MANAGEMENT API TEST")
    print("=" * 75)

    # 1. Service information

    info = get("/info")

    assert info["persistent_storage"]
    assert info["simulation_only"]

    assert not info[
        "real_network_execution_enabled"
    ]

    print("\nService information API: PASSED")

    # 2. Summary

    summary = get("/summary")

    assert summary["total_incidents"] == 6
    assert summary["open_incidents"] == 6
    assert summary["critical_incidents"] == 4
    assert summary["high_incidents"] == 2

    print("\nINCIDENT SUMMARY")

    for key, value in summary.items():
        print(f"{key}: {value}")

    print("Summary API: PASSED")

    # 3. Incident listing

    listing = get(
        params={"limit": 100}
    )

    assert listing["total"] == 6
    assert listing["returned"] == 6

    incidents = listing["incidents"]

    print("\nIncident listing API: PASSED")

    # 4. Filters

    critical = get(
        params={
            "severity": "critical"
        }
    )

    assert critical["total"] == 4

    high = get(
        params={
            "severity": "high"
        }
    )

    assert high["total"] == 2

    mirai = get(
        params={
            "predicted_family": "Mirai"
        }
    )

    assert mirai["total"] == 6

    open_records = get(
        params={
            "status": "open"
        }
    )

    assert open_records["total"] == 6

    print("Filtering API: PASSED")

    # 5. Pagination

    first_page = get(
        params={
            "limit": 2,
            "offset": 0,
        }
    )

    second_page = get(
        params={
            "limit": 2,
            "offset": 2,
        }
    )

    first_ids = {
        row["incident_id"]
        for row in first_page["incidents"]
    }

    second_ids = {
        row["incident_id"]
        for row in second_page["incidents"]
    }

    assert len(first_ids) == 2
    assert len(second_ids) == 2

    assert first_ids.isdisjoint(
        second_ids
    )

    print("Pagination API: PASSED")

    # 6. Incident details and audit history

    originals = {}

    for incident in incidents:

        incident_id = incident["incident_id"]

        detail = get(
            f"/{incident_id}"
        )

        audit = get(
            f"/{incident_id}/audit"
        )

        assert detail["status"] == "open"

        assert detail[
            "allowed_next_statuses"
        ] == ["acknowledged"]

        assert audit["total_events"] == 1

        event = audit["audit_logs"][0]

        assert event["event_sequence"] == 1

        assert event["action"] == (
            "incident_registered"
        )

        assert event["simulation_only"]

        assert not event[
            "actor_authenticated"
        ]

        originals[incident_id] = (
            detail,
            audit,
        )

        print(
            incident_id,
            "|",
            detail["severity"],
            "| Detail and audit: PASSED",
        )

    # 7. Invalid requests

    incident_id = incidents[0]["incident_id"]

    expect_status(
        requests.get(
            BASE_URL,
            params={"limit": 0},
            timeout=TIMEOUT,
        ),
        422,
        "Invalid limit",
    )

    expect_status(
        requests.get(
            BASE_URL,
            params={"offset": -1},
            timeout=TIMEOUT,
        ),
        422,
        "Invalid offset",
    )

    expect_status(
        requests.get(
            BASE_URL,
            params={"severity": "invalid"},
            timeout=TIMEOUT,
        ),
        422,
        "Invalid severity",
    )

    expect_status(
        requests.get(
            BASE_URL,
            params={"status": "invalid"},
            timeout=TIMEOUT,
        ),
        422,
        "Invalid status filter",
    )

    expect_status(
        requests.get(
            BASE_URL + "/invalid-uuid",
            timeout=TIMEOUT,
        ),
        422,
        "Invalid UUID",
    )

    expect_status(
        requests.get(
            BASE_URL + f"/{uuid4()}",
            timeout=TIMEOUT,
        ),
        404,
        "Unknown incident",
    )

    # 8. Invalid lifecycle transition

    expect_status(
        requests.patch(
            BASE_URL + f"/{incident_id}/status",
            json={
                "new_status": "resolved",
                "actor_name": "test_analyst",
                "reason": "Invalid transition test.",
            },
            timeout=TIMEOUT,
        ),
        409,
        "Open to resolved rejection",
    )

    # 9. Invalid actor

    expect_status(
        requests.patch(
            BASE_URL + f"/{incident_id}/status",
            json={
                "new_status": "acknowledged",
                "actor_name": "   ",
                "reason": "Invalid actor test.",
            },
            timeout=TIMEOUT,
        ),
        422,
        "Blank actor rejection",
    )

    # 10. Invalid reason

    expect_status(
        requests.patch(
            BASE_URL + f"/{incident_id}/status",
            json={
                "new_status": "acknowledged",
                "actor_name": "test_analyst",
                "reason": "   ",
            },
            timeout=TIMEOUT,
        ),
        422,
        "Blank reason rejection",
    )

    # 11. Reject unexpected authorization fields

    expect_status(
        requests.patch(
            BASE_URL + f"/{incident_id}/status",
            json={
                "new_status": "acknowledged",
                "actor_name": "test_analyst",
                "reason": "Invalid field test.",
                "containment_authorized": True,
            },
            timeout=TIMEOUT,
        ),
        422,
        "Unexpected authorization field",
    )

    # 12. Confirm no permanent changes

    for incident_id, original in originals.items():

        original_detail, original_audit = original

        assert get(
            f"/{incident_id}"
        ) == original_detail

        assert get(
            f"/{incident_id}/audit"
        ) == original_audit

    assert get("/summary") == summary

    print("\nOriginal incident preservation: PASSED")
    print("Original audit preservation: PASSED")

    print("\n" + "=" * 75)
    print("ALL INCIDENT MANAGEMENT API TESTS PASSED")
    print("=" * 75)

    print("API endpoints exercised: 6")
    print("Existing incidents verified: 6")
    print("Existing audit events verified: 6")
    print("Permanent status modifications: 0")
    print("Permanent audit records added: 0")
    print("Actual network actions: 0")


if __name__ == "__main__":
    main()
