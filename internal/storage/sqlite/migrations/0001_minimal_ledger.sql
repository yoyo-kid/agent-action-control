CREATE TABLE action_requests (
    runtime_id TEXT NOT NULL CHECK (length(trim(runtime_id)) > 0),
    request_id TEXT NOT NULL CHECK (length(trim(request_id)) > 0),
    action_digest TEXT NOT NULL CHECK (
        length(action_digest) = 71
        AND action_digest GLOB 'sha256:*'
        AND substr(action_digest, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    action_type TEXT NOT NULL CHECK (
        action_type IN ('EXTERNAL_SEND', 'UPDATE_RESOURCE_ACCESS', 'DELETE')
    ),
    action_schema_version INTEGER NOT NULL DEFAULT 1 CHECK (action_schema_version = 1),
    normalized_action_json TEXT NOT NULL CHECK (
        json_valid(normalized_action_json)
        AND json_type(normalized_action_json) = 'object'
        AND COALESCE(json_extract(normalized_action_json, '$.type') = action_type, 0)
        AND COALESCE(json_extract(normalized_action_json, '$.actor.runtimeId') = runtime_id, 0)
        AND COALESCE(json_type(normalized_action_json, '$.payload.digest') = 'text', 0)
        AND json_type(normalized_action_json, '$.payload.content') IS NULL
        AND json_type(normalized_action_json, '$.payload.body') IS NULL
        AND json_type(normalized_action_json, '$.payload.bytes') IS NULL
    ),
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    PRIMARY KEY (runtime_id, request_id)
) WITHOUT ROWID;

CREATE TABLE decisions (
    decision_id TEXT PRIMARY KEY CHECK (length(trim(decision_id)) > 0),
    runtime_id TEXT NOT NULL,
    request_id TEXT NOT NULL,
    decision_type TEXT NOT NULL CHECK (decision_type IN ('ALLOW', 'DENY')),
    reason_codes_json TEXT NOT NULL CHECK (
        json_valid(reason_codes_json)
        AND json_type(reason_codes_json) = 'array'
    ),
    required_action_types_json TEXT NOT NULL CHECK (
        required_action_types_json IN ('[]', '["REQUIRE_APPROVAL"]')
    ),
    policy_version TEXT NOT NULL CHECK (length(trim(policy_version)) > 0),
    matched_rule_ids_json TEXT NOT NULL CHECK (
        json_valid(matched_rule_ids_json)
        AND json_type(matched_rule_ids_json) = 'array'
    ),
    evaluated_at TEXT NOT NULL CHECK (length(trim(evaluated_at)) > 0),
    UNIQUE (runtime_id, request_id),
    FOREIGN KEY (runtime_id, request_id)
        REFERENCES action_requests (runtime_id, request_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    CHECK (
        (
            decision_type = 'ALLOW'
            AND json_array_length(reason_codes_json) = 0
            AND required_action_types_json = '[]'
        )
        OR
        (
            decision_type = 'DENY'
            AND json_array_length(reason_codes_json) > 0
        )
    ),
    CHECK (
        (
            instr(reason_codes_json, '"DELEGATOR_APPROVAL_REQUIRED"') > 0
            AND required_action_types_json = '["REQUIRE_APPROVAL"]'
        )
        OR
        (
            instr(reason_codes_json, '"DELEGATOR_APPROVAL_REQUIRED"') = 0
            AND required_action_types_json = '[]'
        )
    )
);

CREATE TABLE policy_effects (
    effect_id TEXT PRIMARY KEY CHECK (length(trim(effect_id)) > 0),
    decision_id TEXT NOT NULL,
    effect_type TEXT NOT NULL CHECK (effect_type = 'CREATE_SAFETY_REVIEW'),
    effect_context_json TEXT NOT NULL CHECK (
        json_valid(effect_context_json)
        AND json_type(effect_context_json) = 'object'
    ),
    idempotency_key TEXT NOT NULL UNIQUE CHECK (length(trim(idempotency_key)) > 0),
    dispatch_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (
        dispatch_status IN ('PENDING', 'PROCESSING', 'SUCCEEDED', 'FAILED')
    ),
    attempt_count INTEGER NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    next_attempt_at TEXT,
    last_error TEXT,
    created_at TEXT NOT NULL CHECK (length(trim(created_at)) > 0),
    updated_at TEXT NOT NULL CHECK (length(trim(updated_at)) > 0),
    dispatched_at TEXT,
    FOREIGN KEY (decision_id)
        REFERENCES decisions (decision_id)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    CHECK (
        (dispatch_status = 'SUCCEEDED' AND dispatched_at IS NOT NULL)
        OR
        (dispatch_status <> 'SUCCEEDED' AND dispatched_at IS NULL)
    )
);

CREATE INDEX idx_policy_effects_dispatchable
    ON policy_effects (dispatch_status, next_attempt_at, created_at)
    WHERE dispatch_status IN ('PENDING', 'FAILED');
