import logging

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, ConfigDict
from .multiclass_explainability_service import (
    explain_prediction,
)
from .multiclass_ml_service import (
    predict_traffic,
    predict_batch,
    get_model_info,
)
from .response_policy_service import (
    plan_traffic_response,
    get_response_policy_info,
)
from .context_risk_service import (
    assess_traffic_risk,
)

from .device_context_service import (
    list_device_profiles,
)

logger = logging.getLogger(__name__)


router = APIRouter(
    prefix="/api/multiclass",
    tags=["Multiclass Intrusion Detection"],
)


MAX_BATCH_SIZE = 1000


# --------------------------------------------------
# REQUEST SCHEMAS
# --------------------------------------------------

class PredictionRequest(BaseModel):

    model_config = ConfigDict(extra="forbid")

    # features: dict[str, float | int]
    features: dict

    source: str = Field(
        default="manual",
        max_length=100,
    )


class BatchPredictionRequest(BaseModel):

    model_config = ConfigDict(extra="forbid")

    records: list[dict]

    source: str = Field(
        default="batch",
        max_length=100,
    )

class ExplanationRequest(BaseModel):

    model_config = ConfigDict(extra="forbid")

    features: dict

    top_n: int = Field(
        default=10,
        ge=1,
        le=36,
        strict=True,
    )

    target_class: int | None = Field(
        default=None,
        ge=0,
        le=7,
        strict=True,
    )

    source: str = Field(
        default="manual",
        max_length=100,
    )
# --------------------------------------------------
# MODEL INFORMATION
# --------------------------------------------------

@router.get("/model-info")
def model_information():

    return get_model_info()


class RiskAssessmentRequest(BaseModel):

    model_config = ConfigDict(extra="forbid")

    features: dict

    device_id: str | None = Field(

        default=None,

        min_length=1,

        max_length=100,

        strict=True,
    )

    source: str = Field(

        default="manual",

        max_length=100,
    )

# --------------------------------------------------
# SINGLE PREDICTION
# --------------------------------------------------

@router.post("/predict")
def multiclass_prediction(
    request: PredictionRequest,
):

    try:

        result = predict_traffic(
            request.features
        )

        return {
            **result,
            "source": request.source,
            "incident_created": False,
            "response_executed": False,
            "mode": "prediction_only",
        }

    except ValueError as error:

        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    except Exception as error:

        logger.exception(
            "Multiclass prediction failed."
        )

        raise HTTPException(
            status_code=500,
            detail="Multiclass prediction failed.",
        ) from error


# --------------------------------------------------
# BATCH PREDICTION
# --------------------------------------------------

@router.post("/predict-batch")
def multiclass_batch_prediction(
    request: BatchPredictionRequest,
):

    if not request.records:

        raise HTTPException(
            status_code=422,
            detail="At least one record is required.",
        )

    if len(request.records) > MAX_BATCH_SIZE:

        raise HTTPException(
            status_code=422,
            detail=(
                f"Maximum batch size is "
                f"{MAX_BATCH_SIZE} records."
            ),
        )

    try:

        predictions = predict_batch(
            request.records
        )

        return {
            "total_records": len(predictions),
            "source": request.source,
            "mode": "prediction_only",
            "predictions": predictions,
        }

    except ValueError as error:

        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    except Exception as error:

        logger.exception(
            "Multiclass batch prediction failed."
        )

        raise HTTPException(
            status_code=500,
            detail="Batch prediction failed.",
        ) from error

# --------------------------------------------------
# MULTICLASS SHAP EXPLANATION
# --------------------------------------------------

@router.post("/explain")
def multiclass_explanation(
    request: ExplanationRequest,
):

    try:

        result = explain_prediction(

            features=request.features,

            top_n=request.top_n,

            target_class=request.target_class,
        )

        return {

            **result,

            "source":
                request.source,

            "mode":
                "explanation_only",

            "incident_created":
                False,

            "response_executed":
                False,
        }

    except ValueError as error:

        raise HTTPException(

            status_code=422,

            detail=str(error),

        ) from error

    except Exception as error:

        logger.exception(
            "Multiclass explanation failed."
        )

        raise HTTPException(

            status_code=500,

            detail=(
                "Multiclass explanation failed."
            ),

        ) from error

# --------------------------------------------------
# DEMONSTRATION DEVICE PROFILES
# --------------------------------------------------

@router.get("/device-profiles")
def multiclass_device_profiles():

    devices = list_device_profiles()

    return {

        "total_devices": len(devices),

        "mode": "demonstration_only",

        "devices": devices,
    }


# --------------------------------------------------
# CONTEXT-AWARE RISK ASSESSMENT
# --------------------------------------------------

@router.post("/assess-risk")
def multiclass_risk_assessment(

    request: RiskAssessmentRequest,

):

    try:

        result = assess_traffic_risk(

            features=request.features,

            device_id=request.device_id,
        )

        return {

            **result,

            "source": request.source,
        }

    except (ValueError, OverflowError) as error:

        raise HTTPException(

            status_code=422,

            detail=str(error),

        ) from error

    except Exception as error:

        logger.exception(

            "Context-aware risk assessment failed."
        )

        raise HTTPException(

            status_code=500,

            detail="Risk assessment failed.",

        ) from error

# --------------------------------------------------
# RESPONSE POLICY INFORMATION
# --------------------------------------------------

@router.get("/response-policy")
def response_policy_information():

    return get_response_policy_info()


# --------------------------------------------------
# CONTROLLED RESPONSE PLANNING
# --------------------------------------------------

@router.post("/plan-response")
def multiclass_response_planning(
    request: RiskAssessmentRequest,
):

    try:

        result = plan_traffic_response(
            features=request.features,
            device_id=request.device_id,
        )

        return {
            **result,
            "source": request.source,
        }

    except (ValueError, OverflowError) as error:

        raise HTTPException(
            status_code=422,
            detail=str(error),
        ) from error

    except Exception as error:

        logger.exception(
            "Controlled response planning failed."
        )

        raise HTTPException(
            status_code=500,
            detail="Response planning failed.",
        ) from error
