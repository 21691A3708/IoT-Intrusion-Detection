from uuid import UUID

from .database import engine

from .incident_repository import (
    get_incident,
    list_incidents,
    get_incident_summary,
    lock_incident,
    update_incident_status,
    get_incident_audit_logs,
    get_latest_audit_event,
    insert_incident_audit_event,
)


INCIDENT_POLICY_VERSION = (
    "incident_lifecycle_v1"
)


ALLOWED_TRANSITIONS = {
    "open": ("acknowledged",),
    "acknowledged": ("investigating",),
    "investigating": (
        "resolved",
        "false_positive",
    ),
    "resolved": (),
    "false_positive": (),
}


VALID_SEVERITIES = {
    "low",
    "medium",
    "high",
    "critical",
}


VALID_ATTACK_FAMILIES = {
    "Benign",
    "DDoS",
    "DoS",
    "Reconnaissance",
    "BruteForce",
    "Spoofing",
    "Mirai",
    "WebBased",
}


class IncidentStateError(ValueError):
    pass


class IncidentAuditIntegrityError(RuntimeError):
    pass


def normalize_incident_id(incident_id):

    try:
        return str(UUID(str(incident_id)))

    except (ValueError, TypeError, AttributeError):

        raise ValueError(
            "Invalid incident UUID."
        ) from None


def validate_text(value, name, maximum):

    if not isinstance(value, str):

        raise ValueError(
            f"{name} must be a string."
        )

    value = value.strip()

    if not 1 <= len(value) <= maximum:

        raise ValueError(
            f"{name} must contain between "
            f"1 and {maximum} characters."
        )

    return value


def validate_status_transition(
    previous_status,
    new_status,
):

    if previous_status not in ALLOWED_TRANSITIONS:

        raise IncidentStateError(
            "Unknown current incident status."
        )

    if new_status not in ALLOWED_TRANSITIONS:

        raise ValueError(
            "Unknown requested incident status."
        )

    allowed = ALLOWED_TRANSITIONS[
        previous_status
    ]

    if new_status not in allowed:

        raise IncidentStateError(
            "Invalid incident transition: "
            f"{previous_status} -> {new_status}. "
            f"Allowed transitions: {list(allowed)}"
        )

    return True


def add_lifecycle_information(incident):

    incident["allowed_next_statuses"] = list(
        ALLOWED_TRANSITIONS[
            incident["status"]
        ]
    )

    incident["terminal_state"] = (
        incident["status"] in (
            "resolved",
            "false_positive",
        )
    )

    incident["incident_policy_version"] = (
        INCIDENT_POLICY_VERSION
    )

    incident["analyst_authentication_enabled"] = (
        False
    )

    return incident


def get_incident_management_info():

    return {
        "incident_policy_version":
            INCIDENT_POLICY_VERSION,

        "persistent_storage": True,

        "storage_mode": "postgresql",

        "database_schema": "multiclass",

        "transactional_status_updates": True,

        "persistent_audit_history": True,

        "simulation_only": True,

        "analyst_authentication_enabled": False,

        "real_network_execution_enabled": False,

        "deployment_mode":
            "local_development_only",

        "allowed_transitions": {
            status: list(transitions)
            for status, transitions
            in ALLOWED_TRANSITIONS.items()
        },
    }


def retrieve_incident(incident_id):

    incident_id = normalize_incident_id(
        incident_id
    )

    with engine.connect() as connection:

        incident = get_incident(
            connection,
            incident_id,
        )

    if incident is None:
        raise KeyError("Incident not found.")

    return add_lifecycle_information(
        incident
    )


def retrieve_incidents(
    limit=50,
    offset=0,
    status=None,
    severity=None,
    predicted_family=None,
    source=None,
):

    if type(limit) is not int or not 1 <= limit <= 100:

        raise ValueError(
            "Limit must be an integer from 1 to 100."
        )

    if type(offset) is not int or offset < 0:

        raise ValueError(
            "Offset must be a non-negative integer."
        )

    if status is not None:

        if status not in ALLOWED_TRANSITIONS:
            raise ValueError("Invalid incident status.")

    if severity is not None:

        if severity not in VALID_SEVERITIES:
            raise ValueError("Invalid severity.")

    if predicted_family is not None:

        if predicted_family not in VALID_ATTACK_FAMILIES:
            raise ValueError("Invalid attack family.")

    if source is not None:

        source = validate_text(
            source,
            "source",
            100,
        )

    with engine.connect().execution_options(
        isolation_level="REPEATABLE READ"
    ) as connection:

        with connection.begin():

            result = list_incidents(
                connection=connection,
                limit=limit,
                offset=offset,
                status=status,
                severity=severity,
                predicted_family=predicted_family,
                source=source,
            )

    result["incidents"] = [
        add_lifecycle_information(incident)
        for incident in result["incidents"]
    ]

    return result


def retrieve_incident_summary():

    with engine.connect() as connection:

        summary = get_incident_summary(
            connection
        )

    summary["storage_mode"] = "postgresql"
    summary["simulation_only"] = True

    return summary


def retrieve_incident_audit(incident_id):

    incident_id = normalize_incident_id(
        incident_id
    )

    with engine.connect().execution_options(
        isolation_level="REPEATABLE READ"
    ) as connection:

        with connection.begin():

            incident = get_incident(
                connection,
                incident_id,
            )

            if incident is None:
                raise KeyError("Incident not found.")

            audit_logs = get_incident_audit_logs(
                connection,
                incident_id,
            )

    return {
        "incident_id": incident_id,
        "status": incident["status"],
        "total_events": len(audit_logs),
        "audit_logs": audit_logs,
        "persistent_storage": True,
        "simulation_only": True,
    }


def change_status_in_transaction(
    connection,
    incident_id,
    new_status,
    actor_name,
    reason,
):

    incident_id = normalize_incident_id(
        incident_id
    )

    actor_name = validate_text(
        actor_name,
        "actor_name",
        100,
    )

    reason = validate_text(
        reason,
        "reason",
        1000,
    )

    if not isinstance(new_status, str):

        raise ValueError(
            "Status must be a string."
        )

    if new_status not in ALLOWED_TRANSITIONS:

        raise ValueError(
            "Invalid incident status."
        )

    # Lock the incident until the transaction ends.

    incident = lock_incident(
        connection,
        incident_id,
    )

    if incident is None:
        raise KeyError("Incident not found.")

    previous_status = incident["status"]

    validate_status_transition(
        previous_status,
        new_status,
    )

    # Verify that audit history matches the incident.

    latest_event = get_latest_audit_event(
        connection,
        incident_id,
    )

    if latest_event is None:

        raise IncidentAuditIntegrityError(
            "Incident audit registration is missing."
        )

    if latest_event["new_status"] != previous_status:

        raise IncidentAuditIntegrityError(
            "Incident status and audit history disagree."
        )

    event_sequence = (
        latest_event["event_sequence"] + 1
    )

    # Update incident status.

    updated = update_incident_status(
        connection=connection,
        incident_id=incident_id,
        previous_status=previous_status,
        new_status=new_status,
    )

    if updated is None:

        raise IncidentStateError(
            "Incident status update conflict."
        )

    # Store audit event in the same transaction.

    audit_event = insert_incident_audit_event(
        connection=connection,
        incident_id=incident_id,
        event_sequence=event_sequence,
        actor_name=actor_name,
        action="status_changed",
        previous_status=previous_status,
        new_status=new_status,
        reason=reason,
        details={
            "incident_policy_version":
                INCIDENT_POLICY_VERSION,

            "real_network_action_executed":
                False,

            "containment_authorized":
                False,
        },
    )

    result = get_incident(
        connection,
        incident_id,
    )

    return {
        "incident": add_lifecycle_information(
            result
        ),
        "audit_event": audit_event,
        "previous_status": previous_status,
        "new_status": new_status,
        "persistent_storage": True,
        "simulation_only": True,
        "real_network_action_executed": False,
        "containment_authorized": False,
    }


def change_incident_status(
    incident_id,
    new_status,
    actor_name,
    reason,
):

    with engine.begin() as connection:

        result = change_status_in_transaction(
            connection=connection,
            incident_id=incident_id,
            new_status=new_status,
            actor_name=actor_name,
            reason=reason,
        )

    return result
