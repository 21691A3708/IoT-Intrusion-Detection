BEGIN;

-- ==================================================
-- MULTICLASS INTRUSION DETECTION DATABASE
-- Migration: 001
-- ==================================================

CREATE SCHEMA multiclass;

REVOKE ALL ON SCHEMA multiclass
FROM PUBLIC, anon, authenticated;


-- ==================================================
-- TABLE 1: MULTICLASS PREDICTIONS
-- ==================================================

CREATE TABLE multiclass.predictions (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    device_id UUID
        REFERENCES public.devices(id)
        ON DELETE SET NULL,

    requested_device_identifier TEXT,

    predicted_label SMALLINT NOT NULL,

    predicted_family TEXT NOT NULL,

    prediction_confidence DOUBLE PRECISION NOT NULL,

    raw_attack_probability DOUBLE PRECISION NOT NULL,

    calibrated_attack_probability DOUBLE PRECISION NOT NULL,

    class_probabilities JSONB NOT NULL,

    detection_status TEXT NOT NULL,

    high_confidence_alert BOOLEAN NOT NULL DEFAULT FALSE,

    features JSONB NOT NULL,

    source TEXT NOT NULL DEFAULT 'manual',

    model_version TEXT NOT NULL,

    prediction_details JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT mc_prediction_label_check
        CHECK (predicted_label BETWEEN 0 AND 7),

    CONSTRAINT mc_prediction_family_check
        CHECK (
            (predicted_label = 0 AND predicted_family = 'Benign')
            OR
            (predicted_label = 1 AND predicted_family = 'DDoS')
            OR
            (predicted_label = 2 AND predicted_family = 'DoS')
            OR
            (predicted_label = 3 AND predicted_family = 'Reconnaissance')
            OR
            (predicted_label = 4 AND predicted_family = 'BruteForce')
            OR
            (predicted_label = 5 AND predicted_family = 'Spoofing')
            OR
            (predicted_label = 6 AND predicted_family = 'Mirai')
            OR
            (predicted_label = 7 AND predicted_family = 'WebBased')
        ),

    CONSTRAINT mc_prediction_confidence_check
        CHECK (prediction_confidence BETWEEN 0 AND 1),

    CONSTRAINT mc_raw_probability_check
        CHECK (raw_attack_probability BETWEEN 0 AND 1),

    CONSTRAINT mc_calibrated_probability_check
        CHECK (calibrated_attack_probability BETWEEN 0 AND 1),

    CONSTRAINT mc_detection_status_check
        CHECK (
            detection_status IN (
                'low_probability',
                'suspicious',
                'elevated_suspicion',
                'high_confidence_attack'
            )
        ),

    CONSTRAINT mc_prediction_json_check
        CHECK (
            jsonb_typeof(features) = 'object'
            AND
            jsonb_typeof(class_probabilities) = 'object'
            AND
            jsonb_typeof(prediction_details) = 'object'
        )
);


-- ==================================================
-- TABLE 2: CONTEXT-AWARE RISK ASSESSMENTS
-- ==================================================

CREATE TABLE multiclass.risk_assessments (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    prediction_id UUID NOT NULL
        REFERENCES multiclass.predictions(id)
        ON DELETE RESTRICT,

    attack_probability DOUBLE PRECISION NOT NULL,

    device_criticality DOUBLE PRECISION NOT NULL,

    device_exposure DOUBLE PRECISION NOT NULL,

    expected_attack_impact DOUBLE PRECISION NOT NULL,

    risk_score DOUBLE PRECISION NOT NULL,

    risk_level TEXT NOT NULL,

    device_context JSONB NOT NULL,

    risk_factors JSONB NOT NULL,

    risk_weights JSONB NOT NULL,

    risk_contributions JSONB NOT NULL,

    recommended_action TEXT NOT NULL,

    risk_policy_version TEXT NOT NULL,

    assessment_details JSONB NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT mc_risk_probability_check
        CHECK (attack_probability BETWEEN 0 AND 1),

    CONSTRAINT mc_criticality_check
        CHECK (device_criticality BETWEEN 0 AND 1),

    CONSTRAINT mc_exposure_check
        CHECK (device_exposure BETWEEN 0 AND 1),

    CONSTRAINT mc_impact_check
        CHECK (expected_attack_impact BETWEEN 0 AND 1),

    CONSTRAINT mc_risk_score_check
        CHECK (risk_score BETWEEN 0 AND 100),

    CONSTRAINT mc_risk_level_check
        CHECK (
            (risk_score < 25 AND risk_level = 'low')
            OR
            (risk_score >= 25 AND risk_score < 50
                AND risk_level = 'medium')
            OR
            (risk_score >= 50 AND risk_score < 75
                AND risk_level = 'high')
            OR
            (risk_score >= 75 AND risk_level = 'critical')
        ),

    CONSTRAINT mc_risk_json_check
        CHECK (
            jsonb_typeof(device_context) = 'object'
            AND
            jsonb_typeof(risk_factors) = 'object'
            AND
            jsonb_typeof(risk_weights) = 'object'
            AND
            jsonb_typeof(risk_contributions) = 'object'
            AND
            jsonb_typeof(assessment_details) = 'object'
        )
);


-- ==================================================
-- TABLE 3: MULTICLASS INCIDENTS
-- ==================================================

CREATE TABLE multiclass.incidents (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    risk_assessment_id UUID NOT NULL UNIQUE
        REFERENCES multiclass.risk_assessments(id)
        ON DELETE RESTRICT,

    title TEXT NOT NULL,

    description TEXT,

    severity TEXT NOT NULL,

    status TEXT NOT NULL DEFAULT 'open',

    assigned_to UUID
        REFERENCES auth.users(id)
        ON DELETE SET NULL,

    resolved_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT mc_incident_severity_check
        CHECK (
            severity IN (
                'low',
                'medium',
                'high',
                'critical'
            )
        ),

    CONSTRAINT mc_incident_status_check
        CHECK (
            status IN (
                'open',
                'acknowledged',
                'investigating',
                'resolved',
                'false_positive'
            )
        )
);


-- ==================================================
-- TABLE 4: CONTROLLED RESPONSE RECORDS
-- ==================================================

CREATE TABLE multiclass.response_records (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    risk_assessment_id UUID NOT NULL UNIQUE
        REFERENCES multiclass.risk_assessments(id)
        ON DELETE RESTRICT,

    status TEXT NOT NULL,

    response_policy_version TEXT NOT NULL,

    response_plan JSONB NOT NULL,

    proposed_containment_action TEXT,

    containment_eligible BOOLEAN NOT NULL DEFAULT FALSE,

    approval_granted BOOLEAN NOT NULL DEFAULT FALSE,

    simulation_authorized BOOLEAN NOT NULL DEFAULT FALSE,

    containment_authorized BOOLEAN NOT NULL DEFAULT FALSE,

    simulation_executed BOOLEAN NOT NULL DEFAULT FALSE,

    real_network_action_executed BOOLEAN NOT NULL DEFAULT FALSE,

    simulation_only BOOLEAN NOT NULL DEFAULT TRUE,

    synthetic_fixture BOOLEAN NOT NULL DEFAULT FALSE,

    approval_details JSONB,

    execution_details JSONB,

    rollback_details JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT mc_response_status_check
        CHECK (
            status IN (
                'not_required',
                'restricted',
                'pending_approval',
                'approved',
                'rejected',
                'simulated',
                'rolled_back'
            )
        ),

    CONSTRAINT mc_response_action_check
        CHECK (
            proposed_containment_action IS NULL
            OR
            proposed_containment_action IN (
                'simulate_device_isolation',
                'simulate_rate_limiting',
                'simulate_traffic_filtering'
            )
        ),

    CONSTRAINT mc_response_simulation_only_check
        CHECK (simulation_only IS TRUE),

    CONSTRAINT mc_response_no_real_execution_check
        CHECK (real_network_action_executed IS FALSE),

    CONSTRAINT mc_response_no_containment_check
        CHECK (containment_authorized IS FALSE),

    CONSTRAINT mc_response_fixture_safety_check
        CHECK (
            synthetic_fixture
            OR (
                status IN ('restricted', 'not_required')
                AND NOT containment_eligible
                AND NOT approval_granted
                AND NOT simulation_authorized
                AND NOT simulation_executed
            )
        ),

    CONSTRAINT mc_response_execution_check
        CHECK (
            NOT simulation_executed
            OR (
                approval_granted
                AND containment_eligible
                AND synthetic_fixture
            )
        ),

    CONSTRAINT mc_response_plan_json_check
        CHECK (jsonb_typeof(response_plan) = 'object')
);


-- ==================================================
-- TABLE 5: RESPONSE AUDIT LOGS
-- ==================================================

CREATE TABLE multiclass.response_audit_logs (

    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    response_id UUID NOT NULL
        REFERENCES multiclass.response_records(id)
        ON DELETE RESTRICT,

    event_sequence INTEGER NOT NULL,

    actor_user_id UUID
        REFERENCES auth.users(id)
        ON DELETE SET NULL,

    actor_name TEXT NOT NULL,

    actor_authenticated BOOLEAN NOT NULL DEFAULT FALSE,

    action TEXT NOT NULL,

    previous_status TEXT,

    new_status TEXT NOT NULL,

    details JSONB NOT NULL DEFAULT '{}'::jsonb,

    simulation_only BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT mc_audit_sequence_check
        CHECK (event_sequence > 0),

    CONSTRAINT mc_audit_sequence_unique
        UNIQUE (response_id, event_sequence),

    CONSTRAINT mc_audit_simulation_check
        CHECK (simulation_only IS TRUE),

    CONSTRAINT mc_audit_details_check
        CHECK (jsonb_typeof(details) = 'object')
);


-- ==================================================
-- INDEXES
-- ==================================================

CREATE INDEX idx_mc_predictions_created
    ON multiclass.predictions(created_at DESC);

CREATE INDEX idx_mc_predictions_family
    ON multiclass.predictions(
        predicted_family,
        created_at DESC
    );

CREATE INDEX idx_mc_predictions_device
    ON multiclass.predictions(device_id);

CREATE INDEX idx_mc_risk_prediction
    ON multiclass.risk_assessments(prediction_id);

CREATE INDEX idx_mc_risk_level
    ON multiclass.risk_assessments(
        risk_level,
        created_at DESC
    );

CREATE INDEX idx_mc_incidents_status
    ON multiclass.incidents(
        status,
        created_at DESC
    );

CREATE INDEX idx_mc_incidents_severity
    ON multiclass.incidents(
        severity,
        created_at DESC
    );

CREATE INDEX idx_mc_responses_status
    ON multiclass.response_records(
        status,
        created_at DESC
    );


-- ==================================================
-- ROW LEVEL SECURITY
-- ==================================================

ALTER TABLE multiclass.predictions
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE multiclass.risk_assessments
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE multiclass.incidents
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE multiclass.response_records
    ENABLE ROW LEVEL SECURITY;

ALTER TABLE multiclass.response_audit_logs
    ENABLE ROW LEVEL SECURITY;


-- ==================================================
-- PREVENT DIRECT CLIENT ACCESS
-- ==================================================

REVOKE ALL ON ALL TABLES IN SCHEMA multiclass
FROM PUBLIC, anon, authenticated;


COMMIT;
