import logging

from typing import Literal
from uuid import UUID

from fastapi import (
    APIRouter,
    HTTPException,
    Query,
)

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
)

from .incident_management_service import (
    IncidentStateError,
    IncidentAuditIntegrityError,
    get_incident_management_info,
    retrieve_incidents,
    retrieve_incident,
    retrieve_incident_summary,
    retrieve_incident_audit,
    change_incident_status,
)


logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api/multiclass/incidents",
    tags=["Multiclass Incident Management"],
)


IncidentStatus = Literal[
    "open",
    "acknowledged",
    "investigating",
    "resolved",
    "false_positive",
]


IncidentSeverity = Literal[
    "low",
    "medium",
    "high",
    "critical",
]


AttackFamily = Literal[
    "Benign",
    "DDoS",
    "DoS",
    "Reconnaissance",
    "BruteForce",
    "Spoofing",
    "Mirai",
    "WebBased",
]


class IncidentStatusRequest(BaseModel):

    model_config = ConfigDict(
        extra="forbid"
    )

    new_status: IncidentStatus

    actor_name: StrictStr = Field(
        min_length=1,
        max_length=100,
    )

    reason: StrictStr = Field(
        min_length=1,
        max_length=1000,
    )


def handle_service_error(error):

    if isinstance(error, KeyError):

        raise HTTPException(
            status_code=404,
            detail="Incident not found.",
        ) from error

    if isinstance(error, IncidentStateError):

        raise HTTPException(
            status_code=409,
            detail=str(error),
        ) from error

    if isinstance(
        error,
        IncidentAuditIntegrityError,
    ):

        logger.error(
            "Incident audit integrity failure",
            exc_info=True,
        )

        raise HTTPException(
            status_code=409,
            detail=(
                "Incident audit integrity check failed."
            ),
        ) from error

    if isinstance(error, ValueError):

        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    logger.error(
        "Incident management operation failed",
        exc_info=True,
    )

    raise HTTPException(
        status_code=500,
        detail="Incident management operation failed.",
    ) from error


@router.get("/info")
def incident_management_info():

    return get_incident_management_info()


@router.get("")
def list_incidents_endpoint(

    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),

    offset: int = Query(
        default=0,
        ge=0,
    ),

    status: IncidentStatus | None = None,

    severity: IncidentSeverity | None = None,

    predicted_family: AttackFamily | None = None,

    source: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
    ),
):

    try:

        return retrieve_incidents(
            limit=limit,
            offset=offset,
            status=status,
            severity=severity,
            predicted_family=predicted_family,
            source=source,
        )

    except Exception as error:

        handle_service_error(error)


@router.get("/summary")
def incident_summary_endpoint():

    try:

        return retrieve_incident_summary()

    except Exception as error:

        handle_service_error(error)


@router.get("/{incident_id}")
def incident_detail_endpoint(
    incident_id: UUID,
):

    try:

        return retrieve_incident(
            str(incident_id)
        )

    except Exception as error:

        handle_service_error(error)


@router.get("/{incident_id}/audit")
def incident_audit_endpoint(
    incident_id: UUID,
):

    try:

        return retrieve_incident_audit(
            str(incident_id)
        )

    except Exception as error:

        handle_service_error(error)


@router.patch("/{incident_id}/status")
def incident_status_endpoint(
    incident_id: UUID,
    request: IncidentStatusRequest,
):

    try:

        return change_incident_status(
            incident_id=str(incident_id),
            new_status=request.new_status,
            actor_name=request.actor_name,
            reason=request.reason,
        )

    except Exception as error:

        handle_service_error(error)
