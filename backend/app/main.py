import json
from datetime import datetime, timezone
from typing import Literal
from uuid import UUID
from fastapi.encoders import jsonable_encoder
import numpy as np
import pandas as pd
from .multiclass_router import router as multiclass_router
from .response_lifecycle_router import router as response_lifecycle_router
from .persistent_response_router import router as persistent_response_router
from fastapi import (
    FastAPI,
    HTTPException,
    Query,
    UploadFile,
    File,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.database import (
    check_database_connection,
    SessionLocal,
)

from app.ml_service import (
    EXPECTED_FEATURES,
    predict_traffic,
    predict_batch,
)

from .explainability_service import explain_prediction
from app.ai_agent import IoTSecurityAgent
app = FastAPI(
    title="IoT Intrusion Detection API",
    description="API for explainable IoT intrusion detection and incident response",
    version="0.1.0",
)

app.include_router(multiclass_router)
app.include_router(response_lifecycle_router)
app.include_router(persistent_response_router)
# Reuse one agent instance for chatbot requests.
assistant_agent = IoTSecurityAgent()

# --------------------------------------------------
# WEBSOCKET CONNECTION MANAGER
# --------------------------------------------------

class PredictionConnectionManager:

    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(
            f"WebSocket connected. Active clients: "
            f"{len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

        print(
            f"WebSocket disconnected. Active clients: "
            f"{len(self.active_connections)}"
        )

    async def broadcast(self, message: dict):
        disconnected = []

        for connection in self.active_connections.copy():
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)

        for connection in disconnected:
            self.disconnect(connection)


prediction_manager = PredictionConnectionManager()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    return {
        "message": "IoT Intrusion Detection API is running",
        "docs": "/docs",
    }


@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "service": "iot-intrusion-detection-api",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
@app.get("/api/health/database")
def database_health():
    try:
        check_database_connection()
        return {
            "status": "healthy",
            "database": "connected",
        }
    except Exception:
        raise HTTPException(
            status_code=503,
            detail="Database connection failed. Check backend configuration.",
        )

class DeviceCreate(BaseModel):
    device_name: str = Field(min_length=1, max_length=150)
    device_identifier: str = Field(min_length=1, max_length=200)
    device_type: str = Field(default="iot", max_length=100)
    location: str | None = Field(default=None, max_length=200)
    status: Literal["online", "offline", "unknown", "quarantined"] = "unknown"


class DeviceResponse(BaseModel):
    id: UUID
    device_name: str
    device_identifier: str
    device_type: str
    location: str | None
    status: str
    last_seen_at: datetime | None
    created_at: datetime


@app.post("/api/devices", response_model=DeviceResponse, status_code=201)
def create_device(device: DeviceCreate):
    try:
        with SessionLocal() as db:
            result = db.execute(
                text("""
                    INSERT INTO public.devices
                        (device_name, device_identifier, device_type, location, status)
                    VALUES
                        (:device_name, :device_identifier, :device_type, :location, :status)
                    RETURNING id, device_name, device_identifier, device_type,
                              location, status, last_seen_at, created_at
                """),
                device.model_dump(),
            )
            row = result.mappings().one()
            db.commit()
            return dict(row)

    except IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="A device with this identifier already exists.",
        )


@app.get("/api/devices", response_model=list[DeviceResponse])
def list_devices():
    with SessionLocal() as db:
        result = db.execute(
            text("""
                SELECT id, device_name, device_identifier, device_type,
                       location, status, last_seen_at, created_at
                FROM public.devices
                ORDER BY created_at DESC
            """)
        )
        return [dict(row) for row in result.mappings().all()]

class PredictionRequest(BaseModel):
    features: dict[str, float]
    device_id: UUID | None = None
    source: Literal["csv_upload", "simulator", "device"] = "simulator"

class ExplainRequest(BaseModel):
    features: dict[str, float]
    top_n: int = 10

class AssistantChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=2000)


class IncidentStatusUpdate(BaseModel):
    status: Literal[
        "acknowledged",
        "investigating",
        "resolved",
        "false_positive"
    ]


@app.post("/api/assistant/chat")
def assistant_chat(request: AssistantChatRequest):
    """Answer a question using the local IoT security agent."""
    try:
        response = assistant_agent.answer_question(request.question)
        return response

    except Exception as exc:
        # Keep internal exception details out of the public API response.
        print("Assistant chat endpoint error:", str(exc))
        raise HTTPException(
            status_code=500,
            detail="The assistant could not process this question."
        ) from exc


@app.post("/api/predictions")
async def create_prediction(request: PredictionRequest):
    # Step 1: Run the ML prediction
    try:
        result = predict_traffic(request.features)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=str(exc),
        ) from exc

    # Step 2: Save prediction and optionally create an incident
    try:
        with SessionLocal() as db:
            row = db.execute(
                text("""
                    INSERT INTO public.predictions (
                        device_id,
                        predicted_label,
                        attack_probability,
                        risk_level,
                        source,
                        features,
                        model_version
                    )
                    VALUES (
                        :device_id,
                        :predicted_label,
                        :attack_probability,
                        :risk_level,
                        :source,
                        CAST(:features AS jsonb),
                        :model_version
                    )
                    RETURNING
                        id,
                        device_id,
                        predicted_label,
                        attack_probability,
                        risk_level,
                        source,
                        model_version,
                        created_at
                """),
                {
                    "device_id": (
                        str(request.device_id)
                        if request.device_id
                        else None
                    ),
                    "predicted_label": result["predicted_label"],
                    "attack_probability": result["attack_probability"],
                    "risk_level": result["risk_level"],
                    "source": request.source,
                    "features": json.dumps(request.features),
                    "model_version": "random_forest_capture_based",
                },
            ).mappings().one()

            # Step 3: Automatically create an incident
            # when the risk level is HIGH or CRITICAL
            incident_id = None

            if result["risk_level"] in ("high", "critical"):
                incident = db.execute(
                    text("""
                        INSERT INTO public.incidents (
                            prediction_id,
                            device_id,
                            title,
                            description,
                            severity,
                            status
                        )
                        VALUES (
                            :prediction_id,
                            :device_id,
                            :title,
                            :description,
                            :severity,
                            'open'
                        )
                        RETURNING id
                    """),
                    {
                        "prediction_id": str(row["id"]),
                        "device_id": (
                            str(request.device_id)
                            if request.device_id
                            else None
                        ),
                        "title": (
                            f"{result['risk_level'].upper()} "
                            "IoT Security Alert"
                        ),
                        "description": (
                            "The intrusion detection model detected "
                            "an attack with "
                            f"{result['attack_probability']:.2%} "
                            "attack probability."
                        ),
                        "severity": result["risk_level"],
                    },
                ).mappings().one()

                incident_id = str(incident["id"])

            # Step 4: Commit prediction and incident together
            db.commit()
            response_data = {
                 **dict(row),
                 "prediction": result["prediction"],
                 "incident_created": incident_id is not None,
                 "incident_id": incident_id,
                 }

           # Step 5: Prepare prediction response
           # Step 6: Broadcast the new prediction to connected clients
            await prediction_manager.broadcast({
                "event": "new_prediction",
                "data": jsonable_encoder(response_data),
                })
            return response_data

    except IntegrityError as exc:
        raise HTTPException(
            status_code=400,
            detail=(
                "The supplied device ID is invalid, or a database "
                "constraint was violated."
            ),
        ) from exc


@app.get("/api/predictions")
def get_predictions(
    limit: int = Query(default=50, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    risk_level: str | None = None,
    predicted_label: int | None = Query(default=None, ge=0, le=1),
):
    try:
        with SessionLocal() as db:

            # Query total number of matching predictions
            count_query = text("""
                SELECT COUNT(*)
                FROM public.predictions
                WHERE
                    (
                        CAST(:risk_level AS VARCHAR) IS NULL
                        OR risk_level = CAST(:risk_level AS VARCHAR)
                    )
                    AND
                    (
                        CAST(:predicted_label AS SMALLINT) IS NULL
                        OR predicted_label = CAST(:predicted_label AS SMALLINT)
                    )
            """)

            total = db.execute(
                count_query,
                {
                    "risk_level": risk_level,
                    "predicted_label": predicted_label,
                },
            ).scalar_one()

            # Retrieve prediction history
            history_query = text("""
                SELECT
                    id,
                    device_id,
                    predicted_label,
                    attack_probability,
                    risk_level,
                    source,
                    model_version,
                    created_at
                FROM public.predictions
                WHERE
                    (
                        CAST(:risk_level AS VARCHAR) IS NULL
                        OR risk_level = CAST(:risk_level AS VARCHAR)
                    )
                    AND
                    (
                        CAST(:predicted_label AS SMALLINT) IS NULL
                        OR predicted_label = CAST(:predicted_label AS SMALLINT)
                    )
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """)

            rows = db.execute(
                history_query,
                {
                    "risk_level": risk_level,
                    "predicted_label": predicted_label,
                    "limit": limit,
                    "offset": offset,
                },
            ).mappings().all()

            return {
                "total": total,
                "limit": limit,
                "offset": offset,
                "items": [dict(row) for row in rows],
            }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Could not retrieve prediction history: {str(e)}",
        )


@app.post("/api/explain")
def explain_traffic(request: ExplainRequest):
    try:
        result = explain_prediction(
            features=request.features,
            top_n=request.top_n
        )

        return {
            "status": "success",
            "explanation": result
        }

    except ValueError as e:
        raise HTTPException(
            status_code=400,
            detail=str(e)
        )

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"SHAP explanation failed: {str(e)}"
        )

        
@app.get("/api/incidents")
def get_incidents(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    status: str | None = None,
):
    try:
        with SessionLocal() as db:

            count_query = text("""
                SELECT COUNT(*)
                FROM public.incidents
                WHERE (
                    CAST(:status AS VARCHAR) IS NULL
                    OR status = CAST(:status AS VARCHAR)
                )
            """)

            total = db.execute(
                count_query,
                {"status": status},
            ).scalar_one()

            incidents_query = text("""
                SELECT
                    id,
                    prediction_id,
                    device_id,
                    title,
                    description,
                    severity,
                    status,
                    assigned_to,
                    resolved_at,
                    created_at
                FROM public.incidents
                WHERE (
                    CAST(:status AS VARCHAR) IS NULL
                    OR status = CAST(:status AS VARCHAR)
                )
                ORDER BY created_at DESC
                LIMIT :limit OFFSET :offset
            """)

            rows = db.execute(
                incidents_query,
                {
                    "status": status,
                    "limit": limit,
                    "offset": offset,
                },
            ).mappings().all()

            return {
                "total": total,
                "limit": limit,
                "offset": offset,
                "items": [dict(row) for row in rows],
            }

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not retrieve incidents: {str(exc)}",
        ) from exc

@app.patch("/api/incidents/{incident_id}/status")
def update_incident_status(
    incident_id: UUID,
    request: IncidentStatusUpdate
):
    try:
        with SessionLocal() as db:

            # 1. Find and lock the incident
            existing = db.execute(
                text("""
                    SELECT id, status
                    FROM public.incidents
                    WHERE id = :incident_id
                    FOR UPDATE
                """),
                {"incident_id": str(incident_id)}
            ).mappings().first()

            if existing is None:
                raise HTTPException(
                    status_code=404,
                    detail="Incident not found."
                )

            old_status = existing["status"]
            new_status = request.status

            # 2. Update the incident status
            updated = db.execute(
                text("""
                    UPDATE public.incidents
                    SET
                        status = :new_status,
                        resolved_at = CASE
                            WHEN :new_status = 'resolved'
                            THEN CURRENT_TIMESTAMP
                            ELSE NULL
                        END
                    WHERE id = :incident_id
                    RETURNING
                        id,
                        prediction_id,
                        device_id,
                        title,
                        severity,
                        status,
                        resolved_at,
                        created_at
                """),
                {
                    "incident_id": str(incident_id),
                    "new_status": new_status
                }
            ).mappings().one()

            # 3. Insert audit log
            audit = db.execute(
                text("""
                    INSERT INTO public.incident_audit_logs (
                        incident_id,
                        action,
                        details
                    )
                    VALUES (
                        :incident_id,
                        :action,
                        CAST(:details AS jsonb)
                    )
                    RETURNING id, created_at
                """),
                {
                    "incident_id": str(incident_id),
                    "action": "status_changed",
                    "details": json.dumps({
                        "old_status": old_status,
                        "new_status": new_status
                    })
                }
            ).mappings().one()

            # 4. Commit both operations together
            db.commit()

            return {
                "message": "Incident status updated successfully.",
                "incident": dict(updated),
                "audit_log": {
                    "id": str(audit["id"]),
                    "action": "status_changed",
                    "old_status": old_status,
                    "new_status": new_status,
                    "created_at": audit["created_at"]
                }
            }

    except HTTPException:
        raise

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Could not update incident: {str(exc)}"
        ) from exc


@app.post("/api/upload/csv")
def upload_csv(file: UploadFile = File(...)):
    """
    Upload an IoT traffic CSV and perform batch intrusion detection.
    Predictions and incidents are saved in a single database transaction.
    """

    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Please upload a valid CSV file."
        )

    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB
    CHUNK_SIZE = 1000
    MAX_ROWS = 500000

    try:
        # Check file size without loading the entire file into memory.
        file.file.seek(0, 2)
        file_size = file.file.tell()
        file.file.seek(0)

        if file_size == 0:
            raise HTTPException(
                status_code=400,
                detail="The uploaded CSV file is empty."
            )

        if file_size > MAX_FILE_SIZE:
            raise HTTPException(
                status_code=413,
                detail="CSV file exceeds the 100 MB upload limit."
            )

        # Read only the CSV header first.
        header = pd.read_csv(file.file, nrows=0, encoding="utf-8-sig")
        file.file.seek(0)

        if header.columns.duplicated().any():
            raise HTTPException(
                status_code=400,
                detail="CSV contains duplicate column names."
            )

        uploaded_columns = list(header.columns)

        missing_features = [
            name for name in EXPECTED_FEATURES
            if name not in uploaded_columns
        ]

        if missing_features:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "CSV is missing required model features.",
                    "missing_features": missing_features
                }
            )

        # These columns are not used by the ML model.
        ignored_columns = {
            "Number",
            "Label",
            "Telnet",
            "SMTP"
        }

        unexpected_columns = [
            name for name in uploaded_columns
            if name not in EXPECTED_FEATURES
            and name not in ignored_columns
        ]

        if unexpected_columns:
            raise HTTPException(
                status_code=422,
                detail={
                    "message": "CSV contains unsupported columns.",
                    "unexpected_columns": unexpected_columns
                }
            )

        summary = {
            "total_records": 0,
            "normal_records": 0,
            "attack_records": 0,
            "risk_distribution": {
                "low": 0,
                "medium": 0,
                "high": 0,
                "critical": 0
            },
            "incidents_created": 0
        }

        with SessionLocal() as db:
            try:
                # Process the CSV in chunks to control memory usage.
                chunks = pd.read_csv(
                    file.file,
                    usecols=EXPECTED_FEATURES,
                    chunksize=CHUNK_SIZE,
                    encoding="utf-8-sig"
                )

                for chunk in chunks:

                    if len(chunk) == 0:
                        continue

                    if summary["total_records"] + len(chunk) > MAX_ROWS:
                        raise HTTPException(
                            status_code=413,
                            detail="CSV exceeds the 500,000 record limit."
                        )

                    # Convert every feature to numeric.
                    for column in EXPECTED_FEATURES:
                        chunk[column] = pd.to_numeric(
                            chunk[column],
                            errors="coerce"
                        )

                    # Reject missing, invalid and infinite values.
                    values = chunk[EXPECTED_FEATURES].to_numpy(
                        dtype=float
                    )

                    if not np.isfinite(values).all():
                        raise HTTPException(
                            status_code=422,
                            detail=(
                                "CSV contains missing, non-numeric, "
                                "or infinite feature values."
                            )
                        )

                    # Run predictions for the complete chunk.
                    predictions = predict_batch(
                        chunk[EXPECTED_FEATURES]
                    )

                    # Save predictions and incidents.
                    for (_, feature_row), result in zip(
                        chunk.iterrows(),
                        predictions
                    ):
                        features = {
                            name: float(feature_row[name])
                            for name in EXPECTED_FEATURES
                        }

                        prediction_row = db.execute(
                            text("""
                                INSERT INTO public.predictions (
                                    device_id,
                                    predicted_label,
                                    attack_probability,
                                    risk_level,
                                    source,
                                    features,
                                    model_version
                                )
                                VALUES (
                                    NULL,
                                    :predicted_label,
                                    :attack_probability,
                                    :risk_level,
                                    'csv_upload',
                                    CAST(:features AS jsonb),
                                    'random_forest_capture_based'
                                )
                                RETURNING id
                            """),
                            {
                                "predicted_label": result["predicted_label"],
                                "attack_probability": result["attack_probability"],
                                "risk_level": result["risk_level"],
                                "features": json.dumps(features)
                            }
                        ).mappings().one()

                        summary["total_records"] += 1

                        if result["predicted_label"] == 1:
                            summary["attack_records"] += 1
                        else:
                            summary["normal_records"] += 1

                        risk = result["risk_level"]
                        summary["risk_distribution"][risk] += 1

                        # Preserve the existing HIGH/CRITICAL incident rule.
                        if risk in ("high", "critical"):
                            db.execute(
                                text("""
                                    INSERT INTO public.incidents (
                                        prediction_id,
                                        device_id,
                                        title,
                                        description,
                                        severity,
                                        status
                                    )
                                    VALUES (
                                        :prediction_id,
                                        NULL,
                                        :title,
                                        :description,
                                        :severity,
                                        'open'
                                    )
                                """),
                                {
                                    "prediction_id": str(
                                        prediction_row["id"]
                                    ),
                                    "title": (
                                        f"{risk.upper()} "
                                        "IoT Security Alert"
                                    ),
                                    "description": (
                                        "CSV batch analysis detected "
                                        "traffic with "
                                        f"{result['attack_probability']:.2%} "
                                        "attack probability."
                                    ),
                                    "severity": risk
                                }
                            )

                            summary["incidents_created"] += 1

                if summary["total_records"] == 0:
                    raise HTTPException(
                        status_code=400,
                        detail="The CSV does not contain any data records."
                    )

                # Commit all uploaded records together.
                db.commit()

            except Exception:
                db.rollback()
                raise

        return {
            "message": "CSV analysis completed successfully.",
            "filename": file.filename,
            **summary
        }

    except HTTPException:
        raise

    except (pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Could not parse the uploaded CSV file."
        ) from exc

    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"CSV processing failed: {str(exc)}"
        ) from exc

    finally:
        file.file.close()
# --------------------------------------------------
# WEBSOCKET: LIVE PREDICTION CONNECTION
# --------------------------------------------------

@app.websocket("/ws/predictions")
async def prediction_websocket(websocket: WebSocket):

    await prediction_manager.connect(websocket)

    try:
        while True:
            # Keep the connection alive and receive client messages.
            await websocket.receive_text()

    except WebSocketDisconnect:
        prediction_manager.disconnect(websocket)