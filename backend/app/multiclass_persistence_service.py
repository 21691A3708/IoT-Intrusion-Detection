from uuid import UUID

from .database import engine
from .incident_repository import register_incident_audit
from .response_lifecycle_service import (
    ResponseLifecycleService,
)

from .multiclass_repository import (
    insert_prediction,
    insert_risk_assessment,
    insert_incident,
    insert_response_record,
    insert_audit_event,
    get_persisted_response,
    list_persisted_responses,
)


# ==================================================
# BUILD SERVER-GENERATED RESPONSE RECORD
# ==================================================

def build_response_record(
    features,
    device_id=None,
):

    service = ResponseLifecycleService(
        max_records=1,
    )

    return service.create_from_traffic(
        features=features,
        device_id=device_id,
    )


# ==================================================
# PERSIST INITIAL RESPONSE RECORD
# ==================================================

def persist_initial_record(
    connection,
    record,
    features,
    device_id=None,
    source="manual",
):

    if not isinstance(source, str):

        raise ValueError(
            "Source must be a string."
        )

    source = source.strip()

    if not source or len(source) > 100:

        raise ValueError(
            "Source must contain 1 to 100 characters."
        )

    if record["synthetic_fixture"]:

        raise ValueError(
            "Synthetic fixture persistence "
            "is not enabled."
        )

    if record["status"] not in (
        "restricted",
        "not_required",
    ):

        raise ValueError(
            "Unexpected initial response status."
        )

    if (
        record["approval_granted"]
        or record["simulation_authorized"]
        or record["simulation_executed"]
        or record["containment_authorized"]
        or record["real_network_action_executed"]
    ):

        raise ValueError(
            "Unsafe initial response record."
        )

    if not record["simulation_only"]:

        raise ValueError(
            "Only simulation records are supported."
        )

    if (
        len(record["audit_logs"]) != 1
        or record["audit_logs"][0]["action"]
        != "response_created"
    ):

        raise ValueError(
            "Expected one initial creation audit event."
        )

    prediction = record["prediction"]

    risk = record["risk_assessment"]

    plan = record["response_plan"]

    # Step 1: Save prediction

    prediction_id = insert_prediction(
        connection=connection,
        prediction=prediction,
        features=features,
        device_identifier=device_id,
        source=source,
    )

    # Step 2: Save risk assessment

    risk_assessment_id = insert_risk_assessment(
        connection=connection,
        prediction_id=prediction_id,
        risk=risk,
    )

    # Step 3: Create incident if required

    incident_id = insert_incident(
        connection=connection,
        risk_assessment_id=risk_assessment_id,
        prediction=prediction,
        risk=risk,
        response_plan=plan,
    )
    if incident_id is not None:
        register_incident_audit(
            connection=connection,
            incident_id=incident_id,
        )

    # Step 4: Save response record

    response_id = insert_response_record(
        connection=connection,
        risk_assessment_id=risk_assessment_id,
        record=record,
    )

    # Step 5: Save audit events

    for sequence, event in enumerate(
        record["audit_logs"],
        start=1,
    ):

        insert_audit_event(
            connection=connection,
            event=event,
            event_sequence=sequence,
        )

    # Retrieve complete saved response

    result = get_persisted_response(
        connection=connection,
        response_id=response_id,
    )

    if result is None:

        raise RuntimeError(
            "Persisted response could not be retrieved."
        )

    if result["incident_id"] != incident_id:

        raise RuntimeError(
            "Incident association mismatch."
        )

    return result


# ==================================================
# CREATE PERSISTENT RESPONSE
# ==================================================

def create_persistent_response(
    features,
    device_id=None,
    source="manual",
):

    record = build_response_record(
        features=features,
        device_id=device_id,
    )

    # Commit on success.
    # Rollback automatically on failure.

    with engine.begin() as connection:

        result = persist_initial_record(
            connection=connection,
            record=record,
            features=features,
            device_id=device_id,
            source=source,
        )

    return result


# ==================================================
# RETRIEVE PERSISTENT RESPONSE
# ==================================================

def retrieve_persistent_response(
    response_id,
):

    response_id = str(
        UUID(str(response_id))
    )

    with engine.connect() as connection:

        result = get_persisted_response(
            connection=connection,
            response_id=response_id,
        )

    if result is None:

        raise KeyError(
            "Response record not found."
        )

    return result


# ==================================================
# LIST PERSISTENT RESPONSES
# ==================================================

def list_persistent_responses(
    limit=50,
    offset=0,
    risk_level=None,
    predicted_family=None,
    status=None,
    source=None,
):

    if type(limit) is not int or not 1 <= limit <= 100:

        raise ValueError(
            "Limit must be between 1 and 100."
        )

    if type(offset) is not int or offset < 0:

        raise ValueError(
            "Offset must be a non-negative integer."
        )

    with engine.connect() as connection:

        connection = connection.execution_options(
            isolation_level="REPEATABLE READ"
        )

        with connection.begin():

            return list_persisted_responses(
                connection=connection,
                limit=limit,
                offset=offset,
                risk_level=risk_level,
                predicted_family=predicted_family,
                status=status,
                source=source,
            )
