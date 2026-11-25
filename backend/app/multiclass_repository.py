import json

from sqlalchemy import text


def to_json(value):
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
    )


# ==================================================
# 1. INSERT PREDICTION
# ==================================================

def insert_prediction(
    connection,
    prediction,
    features,
    device_identifier=None,
    source="manual",
):

    query = text("""
        INSERT INTO multiclass.predictions (
            device_id,
            requested_device_identifier,
            predicted_label,
            predicted_family,
            prediction_confidence,
            raw_attack_probability,
            calibrated_attack_probability,
            class_probabilities,
            detection_status,
            high_confidence_alert,
            features,
            source,
            model_version,
            prediction_details
        )
        VALUES (
            NULL,
            :device_identifier,
            :predicted_label,
            :predicted_family,
            :prediction_confidence,
            :raw_attack_probability,
            :calibrated_attack_probability,
            CAST(:class_probabilities AS JSONB),
            :detection_status,
            :high_confidence_alert,
            CAST(:features AS JSONB),
            :source,
            :model_version,
            CAST(:prediction_details AS JSONB)
        )
        RETURNING id
    """)

    params = {
        "device_identifier": device_identifier,
        "predicted_label": prediction["predicted_label"],
        "predicted_family": prediction["predicted_family"],
        "prediction_confidence":
            prediction["prediction_confidence"],
        "raw_attack_probability":
            prediction["raw_attack_probability"],
        "calibrated_attack_probability":
            prediction["calibrated_attack_probability"],
        "class_probabilities":
            to_json(prediction["class_probabilities"]),
        "detection_status": prediction["detection_status"],
        "high_confidence_alert":
            prediction["high_confidence_alert"],
        "features": to_json(features),
        "source": source,
        "model_version": prediction["model_version"],
        "prediction_details": to_json(prediction),
    }

    return str(
        connection.execute(query, params).scalar_one()
    )


# ==================================================
# 2. INSERT RISK ASSESSMENT
# ==================================================

def insert_risk_assessment(
    connection,
    prediction_id,
    risk,
):

    factors = risk["risk_factors"]

    query = text("""
        INSERT INTO multiclass.risk_assessments (
            prediction_id,
            attack_probability,
            device_criticality,
            device_exposure,
            expected_attack_impact,
            risk_score,
            risk_level,
            device_context,
            risk_factors,
            risk_weights,
            risk_contributions,
            recommended_action,
            risk_policy_version,
            assessment_details
        )
        VALUES (
            :prediction_id,
            :attack_probability,
            :device_criticality,
            :device_exposure,
            :expected_attack_impact,
            :risk_score,
            :risk_level,
            CAST(:device_context AS JSONB),
            CAST(:risk_factors AS JSONB),
            CAST(:risk_weights AS JSONB),
            CAST(:risk_contributions AS JSONB),
            :recommended_action,
            :risk_policy_version,
            CAST(:assessment_details AS JSONB)
        )
        RETURNING id
    """)

    params = {
        "prediction_id": prediction_id,
        "attack_probability": risk["attack_probability"],
        "device_criticality": factors["criticality"],
        "device_exposure": factors["exposure"],
        "expected_attack_impact": factors["attack_impact"],
        "risk_score": risk["risk_score"],
        "risk_level": risk["risk_level"],
        "device_context": to_json(risk["device_context"]),
        "risk_factors": to_json(factors),
        "risk_weights": to_json(risk["risk_weights"]),
        "risk_contributions":
            to_json(risk["risk_contributions"]),
        "recommended_action": risk["recommended_action"],
        "risk_policy_version": risk["risk_policy_version"],
        "assessment_details": to_json(risk),
    }

    return str(
        connection.execute(query, params).scalar_one()
    )


# ==================================================
# 3. INSERT INCIDENT
# ==================================================

def insert_incident(
    connection,
    risk_assessment_id,
    prediction,
    risk,
    response_plan,
):

    if not response_plan["incident_required"]:
        return None

    family = prediction["predicted_family"]

    title = (
        f"Suspected {family} activity"
        if family != "Benign"
        else "Suspicious network activity"
    )

    description = (
        f"Predicted family: {family}. "
        f"Calibrated attack probability: "
        f"{risk['attack_probability']:.4f}. "
        f"Context-aware risk score: "
        f"{risk['risk_score']:.2f}. "
        f"Recommended action: "
        f"{response_plan['primary_action']}. "
        "Device identity is not verified. "
        "Simulation-only investigation."
    )

    query = text("""
        INSERT INTO multiclass.incidents (
            risk_assessment_id,
            title,
            description,
            severity,
            status
        )
        VALUES (
            :risk_assessment_id,
            :title,
            :description,
            :severity,
            'open'
        )
        RETURNING id
    """)

    params = {
        "risk_assessment_id": risk_assessment_id,
        "title": title,
        "description": description,
        "severity": risk["risk_level"],
    }

    return str(
        connection.execute(query, params).scalar_one()
    )


# ==================================================
# 4. INSERT RESPONSE RECORD
# ==================================================

def insert_response_record(
    connection,
    risk_assessment_id,
    record,
):

    plan = record["response_plan"]

    query = text("""
        INSERT INTO multiclass.response_records (
            id,
            risk_assessment_id,
            status,
            response_policy_version,
            response_plan,
            proposed_containment_action,
            containment_eligible,
            approval_granted,
            simulation_authorized,
            containment_authorized,
            simulation_executed,
            real_network_action_executed,
            simulation_only,
            synthetic_fixture,
            created_at,
            updated_at
        )
        VALUES (
            :id,
            :risk_assessment_id,
            :status,
            :response_policy_version,
            CAST(:response_plan AS JSONB),
            :proposed_containment_action,
            :containment_eligible,
            :approval_granted,
            :simulation_authorized,
            :containment_authorized,
            :simulation_executed,
            :real_network_action_executed,
            :simulation_only,
            :synthetic_fixture,
            CAST(:created_at AS TIMESTAMPTZ),
            CAST(:updated_at AS TIMESTAMPTZ)
        )
        RETURNING id
    """)

    params = {
        "id": record["response_id"],
        "risk_assessment_id": risk_assessment_id,
        "status": record["status"],
        "response_policy_version":
            plan["response_policy_version"],
        "response_plan": to_json(plan),
        "proposed_containment_action":
            plan["proposed_containment_action"],
        "containment_eligible": plan["containment_eligible"],
        "approval_granted": record["approval_granted"],
        "simulation_authorized": record["simulation_authorized"],
        "containment_authorized": record["containment_authorized"],
        "simulation_executed": record["simulation_executed"],
        "real_network_action_executed":
            record["real_network_action_executed"],
        "simulation_only": record["simulation_only"],
        "synthetic_fixture": record["synthetic_fixture"],
        "created_at": record["created_at"],
        "updated_at": record["updated_at"],
    }

    return str(
        connection.execute(query, params).scalar_one()
    )


# ==================================================
# 5. INSERT AUDIT EVENT
# ==================================================

def insert_audit_event(
    connection,
    event,
    event_sequence,
):

    query = text("""
        INSERT INTO multiclass.response_audit_logs (
            id,
            response_id,
            event_sequence,
            actor_user_id,
            actor_name,
            actor_authenticated,
            action,
            previous_status,
            new_status,
            details,
            simulation_only,
            created_at
        )
        VALUES (
            :id,
            :response_id,
            :event_sequence,
            NULL,
            :actor_name,
            FALSE,
            :action,
            :previous_status,
            :new_status,
            CAST(:details AS JSONB),
            TRUE,
            CAST(:created_at AS TIMESTAMPTZ)
        )
        RETURNING id
    """)

    params = {
        "id": event["audit_id"],
        "response_id": event["response_id"],
        "event_sequence": event_sequence,
        "actor_name": event["actor"],
        "action": event["action"],
        "previous_status": event["previous_status"],
        "new_status": event["new_status"],
        "details": to_json(event["details"]),
        "created_at": event["timestamp"],
    }

    return str(
        connection.execute(query, params).scalar_one()
    )


# ==================================================
# 6. RETRIEVE PERSISTED RESPONSE
# ==================================================

def get_persisted_response(
    connection,
    response_id,
):

    query = text("""
        SELECT
            r.id AS response_id,
            r.status,
            r.response_plan,
            r.response_policy_version,
            r.containment_eligible,
            r.approval_granted,
            r.simulation_authorized,
            r.containment_authorized,
            r.simulation_executed,
            r.real_network_action_executed,
            r.simulation_only,
            r.synthetic_fixture,
            r.approval_details,
            r.execution_details,
            r.rollback_details,
            r.created_at,
            r.updated_at,

            p.id AS prediction_id,
            p.prediction_details AS prediction,
            p.requested_device_identifier,
            p.source,

            a.id AS risk_assessment_id,
            a.assessment_details AS risk_assessment,

            i.id AS incident_id,
            i.status AS incident_status

        FROM multiclass.response_records r

        JOIN multiclass.risk_assessments a
            ON a.id = r.risk_assessment_id

        JOIN multiclass.predictions p
            ON p.id = a.prediction_id

        LEFT JOIN multiclass.incidents i
            ON i.risk_assessment_id = a.id

        WHERE r.id = :response_id
    """)

    row = connection.execute(
        query,
        {"response_id": response_id},
    ).mappings().one_or_none()

    if row is None:
        return None

    result = dict(row)

    for key in (
        "response_id",
        "prediction_id",
        "risk_assessment_id",
        "incident_id",
    ):
        if result[key] is not None:
            result[key] = str(result[key])

    for key in ("created_at", "updated_at"):
        result[key] = result[key].isoformat()

    audit_query = text("""
        SELECT
            id AS audit_id,
            response_id,
            event_sequence,
            actor_name AS actor,
            actor_authenticated,
            action,
            previous_status,
            new_status,
            details,
            simulation_only,
            created_at AS timestamp

        FROM multiclass.response_audit_logs

        WHERE response_id = :response_id

        ORDER BY event_sequence
    """)

    audit_logs = []

    for event in connection.execute(
        audit_query,
        {"response_id": response_id},
    ).mappings():

        item = dict(event)

        item["audit_id"] = str(item["audit_id"])

        item["response_id"] = str(
            item["response_id"]
        )

        item["timestamp"] = (
            item["timestamp"].isoformat()
        )

        audit_logs.append(item)

    result["audit_logs"] = audit_logs

    result["incident_created"] = (
        result["incident_id"] is not None
    )

    result["storage_mode"] = "postgresql"

    result["response_executed"] = False

    return result


# ==================================================
# 7. LIST PERSISTED RESPONSES
# ==================================================

def list_persisted_responses(
    connection,
    limit=50,
    offset=0,
    risk_level=None,
    predicted_family=None,
    status=None,
    source=None,
):

    conditions = []

    params = {
        "limit": limit,
        "offset": offset,
    }

    if risk_level is not None:
        conditions.append(
            "a.risk_level = :risk_level"
        )
        params["risk_level"] = risk_level

    if predicted_family is not None:
        conditions.append(
            "p.predicted_family = :predicted_family"
        )
        params["predicted_family"] = predicted_family

    if status is not None:
        conditions.append(
            "r.status = :status"
        )
        params["status"] = status

    if source is not None:
        conditions.append(
            "p.source = :source"
        )
        params["source"] = source

    where_clause = (
        "WHERE " + " AND ".join(conditions)
        if conditions
        else ""
    )

    base_query = """
        FROM multiclass.response_records r

        JOIN multiclass.risk_assessments a
            ON a.id = r.risk_assessment_id

        JOIN multiclass.predictions p
            ON p.id = a.prediction_id

        LEFT JOIN multiclass.incidents i
            ON i.risk_assessment_id = a.id
    """

    count_query = text(
        "SELECT COUNT(*) "
        + base_query
        + where_clause
    )

    total = connection.execute(
        count_query,
        params,
    ).scalar_one()

    query = text("""
        SELECT
            r.id AS response_id,
            p.id AS prediction_id,
            a.id AS risk_assessment_id,
            i.id AS incident_id,

            p.requested_device_identifier,
            p.predicted_label,
            p.predicted_family,
            p.prediction_confidence,
            p.calibrated_attack_probability,
            p.detection_status,
            p.model_version,
            p.source,

            a.risk_score,
            a.risk_level,
            a.recommended_action,

            r.status,
            r.containment_eligible,
            r.approval_granted,
            r.simulation_executed,
            r.real_network_action_executed,

            i.status AS incident_status,

            r.created_at,
            r.updated_at
    """
        + base_query
        + where_clause
        + """
        ORDER BY r.created_at DESC, r.id DESC
        LIMIT :limit
        OFFSET :offset
        """
    )

    records = []

    for row in connection.execute(
        query,
        params,
    ).mappings():

        item = dict(row)

        for key in (
            "response_id",
            "prediction_id",
            "risk_assessment_id",
            "incident_id",
        ):
            if item[key] is not None:
                item[key] = str(item[key])

        for key in ("created_at", "updated_at"):
            item[key] = item[key].isoformat()

        item["incident_created"] = (
            item["incident_id"] is not None
        )

        records.append(item)

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "returned": len(records),
        "records": records,
    }
