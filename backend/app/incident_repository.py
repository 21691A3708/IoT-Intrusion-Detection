import json

from sqlalchemy import text


INCIDENT_SELECT = """
    SELECT
        i.id AS incident_id,
        i.risk_assessment_id,
        i.title,
        i.description,
        i.severity,
        i.status,
        i.assigned_to,
        i.resolved_at,
        i.created_at,
        i.updated_at,

        a.risk_score,
        a.risk_level,
        a.recommended_action,
        a.device_context,
        a.risk_policy_version,

        p.id AS prediction_id,
        p.predicted_label,
        p.predicted_family,
        p.prediction_confidence,
        p.calibrated_attack_probability,
        p.detection_status,
        p.requested_device_identifier,
        p.model_version,
        p.source,

        r.id AS response_id,
        r.status AS response_status,
        r.real_network_action_executed,
        r.containment_authorized,
        r.simulation_only

    FROM multiclass.incidents i

    JOIN multiclass.risk_assessments a
        ON a.id = i.risk_assessment_id

    JOIN multiclass.predictions p
        ON p.id = a.prediction_id

    LEFT JOIN multiclass.response_records r
        ON r.risk_assessment_id = a.id
"""


def serialize_row(row):

    if row is None:
        return None

    result = dict(row)

    uuid_fields = (
        "incident_id",
        "risk_assessment_id",
        "prediction_id",
        "response_id",
        "assigned_to",
        "audit_id",
        "actor_user_id",
    )

    for field in uuid_fields:

        if result.get(field) is not None:
            result[field] = str(result[field])

    timestamp_fields = (
        "created_at",
        "updated_at",
        "resolved_at",
    )

    for field in timestamp_fields:

        if result.get(field) is not None:
            result[field] = result[field].isoformat()

    return result


def get_incident(connection, incident_id):

    row = connection.execute(
        text(
            INCIDENT_SELECT
            + """
                WHERE i.id = CAST(:incident_id AS UUID)
            """
        ),
        {"incident_id": str(incident_id)},
    ).mappings().one_or_none()

    return serialize_row(row)


def list_incidents(
    connection,
    limit=50,
    offset=0,
    status=None,
    severity=None,
    predicted_family=None,
    source=None,
):

    conditions = []
    parameters = {}

    filters = {
        "status": ("i.status", status),
        "severity": ("i.severity", severity),
        "predicted_family": (
            "p.predicted_family",
            predicted_family,
        ),
        "source": ("p.source", source),
    }

    for key, (column, value) in filters.items():

        if value is not None:

            conditions.append(
                f"{column} = :{key}"
            )

            parameters[key] = value

    where_clause = ""

    if conditions:

        where_clause = (
            " WHERE "
            + " AND ".join(conditions)
        )

    query = INCIDENT_SELECT + where_clause

    total = connection.execute(
        text(
            "SELECT COUNT(*) FROM ("
            + query
            + ") AS filtered_incidents"
        ),
        parameters,
    ).scalar_one()

    parameters["limit"] = limit
    parameters["offset"] = offset

    rows = connection.execute(
        text(
            query
            + """
                ORDER BY
                    i.created_at DESC,
                    i.id DESC
                LIMIT :limit
                OFFSET :offset
            """
        ),
        parameters,
    ).mappings().all()

    records = [
        serialize_row(row)
        for row in rows
    ]

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "returned": len(records),
        "incidents": records,
    }


def get_incident_summary(connection):

    row = connection.execute(
        text("""
            SELECT
                COUNT(*) AS total_incidents,

                COUNT(*) FILTER (
                    WHERE status = 'open'
                ) AS open_incidents,

                COUNT(*) FILTER (
                    WHERE status = 'acknowledged'
                ) AS acknowledged_incidents,

                COUNT(*) FILTER (
                    WHERE status = 'investigating'
                ) AS investigating_incidents,

                COUNT(*) FILTER (
                    WHERE status = 'resolved'
                ) AS resolved_incidents,

                COUNT(*) FILTER (
                    WHERE status = 'false_positive'
                ) AS false_positive_incidents,

                COUNT(*) FILTER (
                    WHERE severity = 'low'
                ) AS low_incidents,

                COUNT(*) FILTER (
                    WHERE severity = 'medium'
                ) AS medium_incidents,

                COUNT(*) FILTER (
                    WHERE severity = 'high'
                ) AS high_incidents,

                COUNT(*) FILTER (
                    WHERE severity = 'critical'
                ) AS critical_incidents,

                COUNT(*) FILTER (
                    WHERE severity = 'critical'
                    AND status IN (
                        'open',
                        'acknowledged',
                        'investigating'
                    )
                ) AS active_critical_incidents

            FROM multiclass.incidents
        """)
    ).mappings().one()

    result = dict(row)

    result["active_incidents"] = (
        result["open_incidents"]
        + result["acknowledged_incidents"]
        + result["investigating_incidents"]
    )

    return result


def lock_incident(connection, incident_id):

    row = connection.execute(
        text("""
            SELECT
                id AS incident_id,
                status,
                severity,
                resolved_at,
                created_at,
                updated_at

            FROM multiclass.incidents

            WHERE id = CAST(:incident_id AS UUID)

            FOR UPDATE
        """),
        {"incident_id": str(incident_id)},
    ).mappings().one_or_none()

    return serialize_row(row)


def update_incident_status(
    connection,
    incident_id,
    previous_status,
    new_status,
):

    row = connection.execute(
        text("""
            UPDATE multiclass.incidents

            SET
                status = :new_status,

                updated_at = clock_timestamp(),

                resolved_at = CASE

                    WHEN :new_status IN (
                        'resolved',
                        'false_positive'
                    )
                    THEN clock_timestamp()

                    ELSE NULL

                END

            WHERE id = CAST(:incident_id AS UUID)
            AND status = :previous_status

            RETURNING
                id AS incident_id,
                status,
                resolved_at,
                updated_at
        """),
        {
            "incident_id": str(incident_id),
            "previous_status": previous_status,
            "new_status": new_status,
        },
    ).mappings().one_or_none()

    return serialize_row(row)


def get_incident_audit_logs(
    connection,
    incident_id,
):

    rows = connection.execute(
        text("""
            SELECT
                id AS audit_id,
                incident_id,
                event_sequence,
                actor_user_id,
                actor_name,
                actor_authenticated,
                action,
                previous_status,
                new_status,
                reason,
                details,
                simulation_only,
                created_at

            FROM multiclass.incident_audit_logs

            WHERE incident_id =
                CAST(:incident_id AS UUID)

            ORDER BY event_sequence
        """),
        {"incident_id": str(incident_id)},
    ).mappings().all()

    return [
        serialize_row(row)
        for row in rows
    ]


def get_latest_audit_event(
    connection,
    incident_id,
):

    row = connection.execute(
        text("""
            SELECT
                id AS audit_id,
                incident_id,
                event_sequence,
                action,
                previous_status,
                new_status,
                created_at

            FROM multiclass.incident_audit_logs

            WHERE incident_id =
                CAST(:incident_id AS UUID)

            ORDER BY event_sequence DESC

            LIMIT 1
        """),
        {"incident_id": str(incident_id)},
    ).mappings().one_or_none()

    return serialize_row(row)


def insert_incident_audit_event(
    connection,
    incident_id,
    event_sequence,
    actor_name,
    action,
    previous_status,
    new_status,
    reason,
    details=None,
):

    if details is None:
        details = {}

    if not isinstance(details, dict):
        raise ValueError(
            "Audit details must be a dictionary."
        )

    row = connection.execute(
        text("""
            INSERT INTO multiclass.incident_audit_logs (

                incident_id,
                event_sequence,
                actor_user_id,
                actor_name,
                actor_authenticated,
                action,
                previous_status,
                new_status,
                reason,
                details,
                simulation_only,
                created_at

            )

            VALUES (

                CAST(:incident_id AS UUID),
                :event_sequence,
                NULL,
                :actor_name,
                FALSE,
                :action,
                :previous_status,
                :new_status,
                :reason,
                CAST(:details AS JSONB),
                TRUE,
                clock_timestamp()

            )

            RETURNING
                id AS audit_id,
                incident_id,
                event_sequence,
                actor_user_id,
                actor_name,
                actor_authenticated,
                action,
                previous_status,
                new_status,
                reason,
                details,
                simulation_only,
                created_at
        """),
        {
            "incident_id": str(incident_id),
            "event_sequence": event_sequence,
            "actor_name": actor_name,
            "action": action,
            "previous_status": previous_status,
            "new_status": new_status,
            "reason": reason,
            "details": json.dumps(
                details,
                allow_nan=False,
            ),
        },
    ).mappings().one()

    return serialize_row(row)


def register_incident_audit(
    connection,
    incident_id,
):

    incident = lock_incident(
        connection,
        incident_id,
    )

    if incident is None:
        raise KeyError("Incident not found.")

    existing_event = get_latest_audit_event(
        connection,
        incident_id,
    )

    if existing_event is not None:
        raise ValueError(
            "Incident audit is already registered."
        )

    if incident["status"] != "open":
        raise ValueError(
            "New incidents must have open status."
        )

    return insert_incident_audit_event(
        connection=connection,
        incident_id=incident_id,
        event_sequence=1,
        actor_name="system",
        action="incident_registered",
        previous_status=None,
        new_status="open",
        reason="Incident automatically registered.",
        details={
            "migration_backfill": False,
            "severity": incident["severity"],
            "original_created_at":
                incident["created_at"],
        },
    )
