import logging
from typing import Literal
from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from .response_lifecycle_service import (
    ResponseLifecycleService,
    ResponseStateError,
)


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/responses",
    tags=["Controlled Response Lifecycle"],
)

response_service = ResponseLifecycleService(
    max_records=1000,
)


class CreateResponseRequest(BaseModel):

    model_config = ConfigDict(extra="forbid")

    features: dict

    device_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=100,
        strict=True,
    )


class ResponseDecisionRequest(BaseModel):

    model_config = ConfigDict(extra="forbid")

    decision: Literal["approve", "reject"]

    actor: str = Field(
        min_length=1,
        max_length=100,
        strict=True,
    )

    reason: str = Field(
        min_length=1,
        max_length=500,
        strict=True,
    )


class ResponseExecutionRequest(BaseModel):

    model_config = ConfigDict(extra="forbid")

    actor: str = Field(
        min_length=1,
        max_length=100,
        strict=True,
    )


class ResponseRollbackRequest(BaseModel):

    model_config = ConfigDict(extra="forbid")

    actor: str = Field(
        min_length=1,
        max_length=100,
        strict=True,
    )

    reason: str = Field(
        min_length=1,
        max_length=500,
        strict=True,
    )


def handle_service_error(error):

    if isinstance(error, KeyError):

        raise HTTPException(
            status_code=404,
            detail="Response record not found.",
        ) from error

    if isinstance(error, ResponseStateError):

        raise HTTPException(
            status_code=409,
            detail=str(error),
        ) from error

    if isinstance(error, (ValueError, OverflowError)):

        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    logger.exception(
        "Response lifecycle operation failed."
    )

    raise HTTPException(
        status_code=500,
        detail="Response lifecycle operation failed.",
    ) from error


@router.get("/info")
def get_response_lifecycle_info():

    return {
        "service": "controlled_response_lifecycle",
        "version": "response_lifecycle_v1",
        "storage_mode": "in_memory",
        "maximum_records": 1000,
        "persistent_storage": False,
        "simulation_only": True,
        "real_network_execution_enabled": False,
        "analyst_authentication_enabled": False,
        "device_identity_verification_enabled": False,
        "synthetic_fixture_creation_via_api": False,
        "approval_available_for_api_created_records": False,

        "supported_states": [
            "not_required",
            "restricted",
            "pending_approval",
            "approved",
            "rejected",
            "simulated",
            "rolled_back",
        ],

        "allowed_transitions": {
            "pending_approval": [
                "approved",
                "rejected",
            ],
            "approved": ["simulated"],
            "simulated": ["rolled_back"],
            "restricted": [],
            "not_required": [],
            "rejected": [],
            "rolled_back": [],
        },
    }


@router.post("", status_code=201)
def create_response(
    request: CreateResponseRequest,
):

    try:

        return response_service.create_from_traffic(
            features=request.features,
            device_id=request.device_id,
        )

    except Exception as error:

        handle_service_error(error)


@router.get("/{response_id}")
def get_response(
    response_id: UUID,
):

    try:

        return response_service.get_response(
            str(response_id),
        )

    except Exception as error:

        handle_service_error(error)


@router.get("/{response_id}/audit")
def get_response_audit(
    response_id: UUID,
):

    try:

        record = response_service.get_response(
            str(response_id),
        )

        return {
            "response_id": str(response_id),
            "status": record["status"],
            "total_events": len(record["audit_logs"]),
            "audit_logs": record["audit_logs"],
            "persistent_storage": False,
            "simulation_only": True,
        }

    except Exception as error:

        handle_service_error(error)


@router.post("/{response_id}/decision")
def decide_response(
    response_id: UUID,
    request: ResponseDecisionRequest,
):

    try:

        return response_service.decide(
            response_id=str(response_id),
            decision=request.decision,
            actor=request.actor,
            reason=request.reason,
        )

    except Exception as error:

        handle_service_error(error)


@router.post("/{response_id}/execute")
def execute_response(
    response_id: UUID,
    request: ResponseExecutionRequest,
):

    try:

        return response_service.execute(
            response_id=str(response_id),
            actor=request.actor,
        )

    except Exception as error:

        handle_service_error(error)


@router.post("/{response_id}/rollback")
def rollback_response(
    response_id: UUID,
    request: ResponseRollbackRequest,
):

    try:

        return response_service.rollback(
            response_id=str(response_id),
            actor=request.actor,
            reason=request.reason,
        )

    except Exception as error:

        handle_service_error(error)
