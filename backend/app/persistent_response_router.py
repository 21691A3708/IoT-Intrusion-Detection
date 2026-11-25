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
)

from .multiclass_persistence_service import (
    create_persistent_response,
    retrieve_persistent_response,
    list_persistent_responses,
)


logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api/persistent-responses",
    tags=["Persistent Multiclass Responses"],
)


RiskLevel = Literal[
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


ResponseStatus = Literal[
    "not_required",
    "restricted",
    "pending_approval",
    "approved",
    "rejected",
    "simulated",
    "rolled_back",
]


class PersistentResponseRequest(BaseModel):

    model_config = ConfigDict(
        extra="forbid"
    )

    features: dict

    device_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        strict=True,
    )

    source: str = Field(
        default="manual",
        min_length=1,
        max_length=100,
        strict=True,
    )


def handle_error(error):

    if isinstance(error, (ValueError, OverflowError)):

        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    logger.exception(
        "Persistent response operation failed."
    )

    raise HTTPException(
        status_code=500,
        detail="Persistent response operation failed.",
    ) from error


@router.get("/info")
def get_service_information():

    return {
        "service": "persistent_multiclass_responses",

        "version": "persistent_response_v1",

        "storage_mode": "postgresql",

        "database_schema": "multiclass",

        "persistent_storage": True,

        "transactional_writes": True,

        "incident_creation_enabled": True,

        "audit_history_enabled": True,

        "pagination_enabled": True,

        "filtering_enabled": True,

        "simulation_only": True,

        "real_network_execution_enabled": False,

        "analyst_authentication_enabled": False,

        "device_identity_verification_enabled": False,

        "persistent_approval_enabled": False,

        "persistent_execution_enabled": False,

        "persistent_rollback_enabled": False,

        "deployment_mode": "local_development_only",
    }


@router.post("", status_code=201)
def create_response(
    request: PersistentResponseRequest,
):

    try:

        return create_persistent_response(
            features=request.features,
            device_id=request.device_id,
            source=request.source,
        )

    except Exception as error:

        handle_error(error)


@router.get("")
def list_responses(

    limit: int = Query(
        default=50,
        ge=1,
        le=100,
    ),

    offset: int = Query(
        default=0,
        ge=0,
    ),

    risk_level: RiskLevel | None = None,

    predicted_family: AttackFamily | None = None,

    status: ResponseStatus | None = None,

    source: str | None = Query(
        default=None,
        min_length=1,
        max_length=100,
    ),

):

    try:

        return list_persistent_responses(
            limit=limit,
            offset=offset,
            risk_level=risk_level,
            predicted_family=predicted_family,
            status=status,
            source=source,
        )

    except Exception as error:

        handle_error(error)


@router.get("/{response_id}")
def get_response(
    response_id: UUID,
):

    try:

        return retrieve_persistent_response(
            str(response_id)
        )

    except KeyError as error:

        raise HTTPException(
            status_code=404,
            detail="Response record not found.",
        ) from error

    except Exception as error:

        handle_error(error)


@router.get("/{response_id}/audit")
def get_response_audit(
    response_id: UUID,
):

    try:

        record = retrieve_persistent_response(
            str(response_id)
        )

        return {
            "response_id": record["response_id"],

            "status": record["status"],

            "total_events": len(
                record["audit_logs"]
            ),

            "audit_logs": record["audit_logs"],

            "persistent_storage": True,

            "simulation_only": True,
        }

    except KeyError as error:

        raise HTTPException(
            status_code=404,
            detail="Response record not found.",
        ) from error

    except Exception as error:

        handle_error(error)
