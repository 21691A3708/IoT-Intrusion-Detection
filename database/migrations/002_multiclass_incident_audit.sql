BEGIN;

-- =====================================================
-- MULTICLASS INCIDENT AUDIT TABLE
-- =====================================================

CREATE TABLE multiclass.incident_audit_logs (

    id UUID PRIMARY KEY
        DEFAULT gen_random_uuid(),

    incident_id UUID NOT NULL
        REFERENCES multiclass.incidents(id)
        ON DELETE RESTRICT,

    event_sequence INTEGER NOT NULL,

    actor_user_id UUID
        REFERENCES auth.users(id)
        ON DELETE RESTRICT,

    actor_name TEXT NOT NULL,

    actor_authenticated BOOLEAN NOT NULL
        DEFAULT FALSE,

    action TEXT NOT NULL,

    previous_status TEXT,

    new_status TEXT NOT NULL,

    reason TEXT NOT NULL,

    details JSONB NOT NULL
        DEFAULT '{}'::jsonb,

    simulation_only BOOLEAN NOT NULL
        DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL
        DEFAULT NOW(),

    -- Unique sequence for each incident

    CONSTRAINT mc_incident_audit_sequence_unique
        UNIQUE (incident_id, event_sequence),

    CONSTRAINT mc_incident_audit_sequence_check
        CHECK (event_sequence > 0),

    -- Validate actor name

    CONSTRAINT mc_incident_audit_actor_check
        CHECK (
            CHAR_LENGTH(BTRIM(actor_name))
            BETWEEN 1 AND 100
        ),

    -- Authentication remains disabled

    CONSTRAINT mc_incident_audit_auth_check
        CHECK (
            actor_authenticated = FALSE
            AND actor_user_id IS NULL
        ),

    -- Supported audit actions

    CONSTRAINT mc_incident_audit_action_check
        CHECK (
            action IN (
                'incident_registered',
                'status_changed'
            )
        ),

    -- Validate status values

    CONSTRAINT mc_incident_audit_previous_status_check
        CHECK (
            previous_status IS NULL
            OR previous_status IN (
                'open',
                'acknowledged',
                'investigating',
                'resolved',
                'false_positive'
            )
        ),

    CONSTRAINT mc_incident_audit_new_status_check
        CHECK (
            new_status IN (
                'open',
                'acknowledged',
                'investigating',
                'resolved',
                'false_positive'
            )
        ),

    -- Enforce valid audit transitions

    CONSTRAINT mc_incident_audit_transition_check
        CHECK (

            (
                action = 'incident_registered'
                AND previous_status IS NULL
                AND event_sequence = 1
            )

            OR

            (
                action = 'status_changed'
                AND previous_status IS NOT NULL
                AND event_sequence > 1
                AND (

                    (
                        previous_status = 'open'
                        AND new_status = 'acknowledged'
                    )

                    OR

                    (
                        previous_status = 'acknowledged'
                        AND new_status = 'investigating'
                    )

                    OR

                    (
                        previous_status = 'investigating'
                        AND new_status IN (
                            'resolved',
                            'false_positive'
                        )
                    )
                )
            )
        ),

    -- Validate reason

    CONSTRAINT mc_incident_audit_reason_check
        CHECK (
            CHAR_LENGTH(BTRIM(reason))
            BETWEEN 1 AND 1000
        ),

    -- Additional information must be a JSON object

    CONSTRAINT mc_incident_audit_details_check
        CHECK (
            jsonb_typeof(details) = 'object'
        ),

    -- Simulation-only restriction

    CONSTRAINT mc_incident_audit_simulation_check
        CHECK (simulation_only = TRUE)

);


-- =====================================================
-- INDEXES
-- =====================================================

CREATE INDEX idx_mc_incident_audit_created_at
ON multiclass.incident_audit_logs (created_at DESC);


-- =====================================================
-- ROW LEVEL SECURITY
-- =====================================================

ALTER TABLE multiclass.incident_audit_logs
ENABLE ROW LEVEL SECURITY;

REVOKE ALL
ON TABLE multiclass.incident_audit_logs
FROM PUBLIC, anon, authenticated;


-- =====================================================
-- APPEND-ONLY AUDIT PROTECTION
-- =====================================================

CREATE FUNCTION multiclass.prevent_incident_audit_mutation()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN

    RAISE EXCEPTION
        'Incident audit history is append-only';

    RETURN NULL;

END;
$$;


CREATE TRIGGER trg_mc_incident_audit_immutable
BEFORE UPDATE OR DELETE
ON multiclass.incident_audit_logs
FOR EACH ROW
EXECUTE FUNCTION
    multiclass.prevent_incident_audit_mutation();


CREATE TRIGGER trg_mc_incident_audit_no_truncate
BEFORE TRUNCATE
ON multiclass.incident_audit_logs
FOR EACH STATEMENT
EXECUTE FUNCTION
    multiclass.prevent_incident_audit_mutation();


-- =====================================================
-- REGISTER EXISTING INCIDENTS
-- =====================================================

INSERT INTO multiclass.incident_audit_logs (

    incident_id,
    event_sequence,
    actor_name,
    actor_authenticated,
    action,
    previous_status,
    new_status,
    reason,
    details,
    simulation_only

)

SELECT

    id,
    1,
    'system',
    FALSE,
    'incident_registered',
    NULL,
    status,
    'Existing incident registered during audit migration.',

    jsonb_build_object(
        'migration_backfill', TRUE,
        'original_created_at', created_at,
        'severity', severity
    ),

    TRUE

FROM multiclass.incidents;


COMMIT;
