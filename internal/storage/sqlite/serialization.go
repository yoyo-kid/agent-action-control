package sqlite

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/yoyo-kid/agent-action-control/internal/application"
	"github.com/yoyo-kid/agent-action-control/internal/domain"
)

const actionSchemaVersionV1 = 1

type persistedAction struct {
	Schema                string                           `json:"schema"`
	Type                  domain.ActionType                `json:"type"`
	RequestedAt           string                           `json:"requestedAt"`
	Actor                 persistedActor                   `json:"actor"`
	Delegation            persistedDelegation              `json:"delegation"`
	Target                persistedTarget                  `json:"target"`
	Parameters            json.RawMessage                  `json:"parameters"`
	Payload               persistedPayload                 `json:"payload"`
	AuthorizationEvidence []persistedAuthorizationEvidence `json:"authorizationEvidence"`
}

type persistedActor struct {
	AgentID   string `json:"agentId"`
	RuntimeID string `json:"runtimeId"`
	SessionID string `json:"sessionId"`
}

type persistedPrincipal struct {
	Type domain.PrincipalType `json:"type"`
	ID   string               `json:"id"`
}

type persistedDelegation struct {
	ID        string             `json:"id"`
	Delegator persistedPrincipal `json:"delegator"`
}

type persistedTarget struct {
	ResourceType string `json:"resourceType"`
	ResourceID   string `json:"resourceId"`
}

type persistedPayload struct {
	Digest         string   `json:"digest"`
	Classification []string `json:"classification"`
	SizeBytes      *int64   `json:"sizeBytes"`
}

type persistedAuthorizationEvidence struct {
	Type       domain.AuthorizationEvidenceType `json:"type"`
	EvidenceID string                           `json:"evidenceId"`
	IssuedBy   persistedPrincipal               `json:"issuedBy"`
	Scope      persistedAuthorizationScope      `json:"scope"`
}

type persistedAuthorizationScope struct {
	ActionType       domain.ActionType       `json:"actionType"`
	DestinationScope domain.DestinationScope `json:"destinationScope,omitempty"`
	RequestedScope   domain.AccessScope      `json:"requestedScope,omitempty"`
	DeleteMode       domain.DeleteMode       `json:"deleteMode,omitempty"`
}

type persistedExternalSendParameters struct {
	DestinationScope domain.DestinationScope `json:"destinationScope"`
	Recipients       []string                `json:"recipients"`
}

type persistedUpdateResourceAccessParameters struct {
	CurrentScope     domain.AccessScope   `json:"currentScope"`
	RequestedScope   domain.AccessScope   `json:"requestedScope"`
	TargetPrincipals []persistedPrincipal `json:"targetPrincipals"`
}

type persistedDeleteParameters struct {
	DeleteMode  domain.DeleteMode `json:"deleteMode"`
	Recoverable bool              `json:"recoverable"`
}

type persistedSafetyReviewContext struct {
	Priority     domain.SafetyReviewPriority `json:"priority"`
	EvidenceRefs []string                    `json:"evidenceRefs"`
}

type encodedEvaluation struct {
	actionJSON          []byte
	reasonCodesJSON     []byte
	requiredActionsJSON []byte
	matchedRuleIDsJSON  []byte
	effects             []encodedPolicyEffect
}

type encodedPolicyEffect struct {
	effectID       string
	typ            domain.PolicyEffectType
	contextJSON    []byte
	idempotencyKey string
}

func encodeEvaluation(commit application.EvaluationCommit) (encodedEvaluation, error) {
	if strings.TrimSpace(commit.RuntimeID) == "" || strings.TrimSpace(commit.RequestID) == "" {
		return encodedEvaluation{}, fmt.Errorf("%w: runtime ID and request ID are required", application.ErrInvalidInput)
	}
	if commit.Action.Actor().RuntimeID() != commit.RuntimeID {
		return encodedEvaluation{}, fmt.Errorf("%w: authenticated runtime does not match action runtime", application.ErrInvalidInput)
	}
	computedDigest, err := domain.ComputeActionDigest(commit.Action)
	if err != nil {
		return encodedEvaluation{}, fmt.Errorf("%w: compute action digest: %v", application.ErrInvalidInput, err)
	}
	if !commit.ActionDigest.Valid() || computedDigest != commit.ActionDigest {
		return encodedEvaluation{}, fmt.Errorf("%w: action digest does not match normalized action", application.ErrInvalidInput)
	}
	if strings.TrimSpace(commit.DecisionID) == "" || !commit.Decision.Type().Valid() {
		return encodedEvaluation{}, fmt.Errorf("%w: valid decision identity and value are required", application.ErrInvalidInput)
	}
	if strings.TrimSpace(commit.PolicyVersion) == "" || commit.EvaluatedAt.IsZero() {
		return encodedEvaluation{}, fmt.Errorf("%w: policy version and evaluated time are required", application.ErrInvalidInput)
	}
	if err := validateStrings(commit.MatchedRuleIDs, "matched rule ID"); err != nil {
		return encodedEvaluation{}, err
	}

	actionJSON, err := domain.CanonicalActionBytes(commit.Action)
	if err != nil {
		return encodedEvaluation{}, fmt.Errorf("%w: serialize action: %v", application.ErrInvalidInput, err)
	}
	reasons := commit.Decision.ReasonCodes()
	reasonValues := make([]string, 0, len(reasons))
	for _, reason := range reasons {
		if !reason.Valid() {
			return encodedEvaluation{}, fmt.Errorf("%w: invalid decision reason", application.ErrInvalidInput)
		}
		reasonValues = append(reasonValues, string(reason))
	}
	requiredActions := commit.Decision.RequiredActions()
	requiredActionValues := make([]string, 0, len(requiredActions))
	for _, action := range requiredActions {
		if !action.Type().Valid() {
			return encodedEvaluation{}, fmt.Errorf("%w: invalid required action", application.ErrInvalidInput)
		}
		requiredActionValues = append(requiredActionValues, string(action.Type()))
	}

	reasonCodesJSON, _ := json.Marshal(reasonValues)
	requiredActionsJSON, _ := json.Marshal(requiredActionValues)
	matchedRuleIDsJSON, _ := json.Marshal(append([]string(nil), commit.MatchedRuleIDs...))
	effects, err := encodeEffects(commit)
	if err != nil {
		return encodedEvaluation{}, err
	}
	return encodedEvaluation{
		actionJSON:          actionJSON,
		reasonCodesJSON:     reasonCodesJSON,
		requiredActionsJSON: requiredActionsJSON,
		matchedRuleIDsJSON:  matchedRuleIDsJSON,
		effects:             effects,
	}, nil
}

func encodeEffects(commit application.EvaluationCommit) ([]encodedPolicyEffect, error) {
	result := make([]encodedPolicyEffect, 0, len(commit.Effects))
	seenIDs := make(map[string]struct{}, len(commit.Effects))
	seenTypes := make(map[domain.PolicyEffectType]struct{}, len(commit.Effects))
	for _, record := range commit.Effects {
		effectID := strings.TrimSpace(record.EffectID)
		if effectID == "" || record.Effect == nil {
			return nil, fmt.Errorf("%w: policy effect ID and value are required", application.ErrInvalidInput)
		}
		if _, exists := seenIDs[effectID]; exists {
			return nil, fmt.Errorf("%w: duplicate policy effect ID", application.ErrInvalidInput)
		}
		seenIDs[effectID] = struct{}{}
		typ := record.Effect.Type()
		if !typ.Valid() {
			return nil, fmt.Errorf("%w: invalid policy effect type", application.ErrInvalidInput)
		}
		if _, exists := seenTypes[typ]; exists {
			return nil, fmt.Errorf("%w: duplicate policy effect type", application.ErrInvalidInput)
		}
		seenTypes[typ] = struct{}{}

		var contextValue persistedSafetyReviewContext
		switch effect := record.Effect.(type) {
		case domain.CreateSafetyReviewEffect:
			requirement := effect.Requirement()
			contextValue = persistedSafetyReviewContext{
				Priority:     requirement.Priority(),
				EvidenceRefs: requirement.EvidenceRefs(),
			}
		case *domain.CreateSafetyReviewEffect:
			if effect == nil {
				return nil, fmt.Errorf("%w: policy effect cannot be nil", application.ErrInvalidInput)
			}
			requirement := effect.Requirement()
			contextValue = persistedSafetyReviewContext{
				Priority:     requirement.Priority(),
				EvidenceRefs: requirement.EvidenceRefs(),
			}
		default:
			return nil, fmt.Errorf("%w: unsupported policy effect", application.ErrInvalidInput)
		}
		contextJSON, err := json.Marshal(contextValue)
		if err != nil {
			return nil, fmt.Errorf("%w: serialize policy effect: %v", application.ErrInvalidInput, err)
		}
		result = append(result, encodedPolicyEffect{
			effectID:       effectID,
			typ:            typ,
			contextJSON:    contextJSON,
			idempotencyKey: policyEffectIdempotencyKey(commit.RuntimeID, commit.RequestID, typ),
		})
	}
	return result, nil
}

func decodeAction(value []byte) (domain.ProposedAction, error) {
	var stored persistedAction
	if err := json.Unmarshal(value, &stored); err != nil {
		return domain.ProposedAction{}, fmt.Errorf("decode action JSON: %w", err)
	}
	if stored.Schema != domain.CanonicalActionSchemaV1 {
		return domain.ProposedAction{}, fmt.Errorf("unsupported action schema %q", stored.Schema)
	}
	requestedAt, err := time.Parse(time.RFC3339Nano, stored.RequestedAt)
	if err != nil {
		return domain.ProposedAction{}, fmt.Errorf("parse requested time: %w", err)
	}
	actor, err := domain.NewActor(stored.Actor.AgentID, stored.Actor.RuntimeID, stored.Actor.SessionID)
	if err != nil {
		return domain.ProposedAction{}, err
	}
	delegator, err := decodePrincipal(stored.Delegation.Delegator)
	if err != nil {
		return domain.ProposedAction{}, err
	}
	delegation, err := domain.NewDelegation(stored.Delegation.ID, delegator)
	if err != nil {
		return domain.ProposedAction{}, err
	}
	target, err := domain.NewTarget(stored.Target.ResourceType, stored.Target.ResourceID)
	if err != nil {
		return domain.ProposedAction{}, err
	}
	parameters, err := decodeParameters(stored.Type, stored.Parameters)
	if err != nil {
		return domain.ProposedAction{}, err
	}
	payloadDigest, err := domain.ParsePayloadDigest(stored.Payload.Digest)
	if err != nil {
		return domain.ProposedAction{}, err
	}
	payload, err := domain.NewPayloadFacts(payloadDigest, stored.Payload.Classification, stored.Payload.SizeBytes)
	if err != nil {
		return domain.ProposedAction{}, err
	}
	evidence := make([]domain.AuthorizationEvidence, 0, len(stored.AuthorizationEvidence))
	for _, item := range stored.AuthorizationEvidence {
		issuer, err := decodePrincipal(item.IssuedBy)
		if err != nil {
			return domain.ProposedAction{}, err
		}
		scope, err := domain.NewAuthorizationScope(
			item.Scope.ActionType,
			item.Scope.DestinationScope,
			item.Scope.RequestedScope,
			item.Scope.DeleteMode,
		)
		if err != nil {
			return domain.ProposedAction{}, err
		}
		evidenceType, err := domain.ParseAuthorizationEvidenceType(string(item.Type))
		if err != nil {
			return domain.ProposedAction{}, err
		}
		decoded, err := domain.NewAuthorizationEvidence(evidenceType, item.EvidenceID, issuer, scope)
		if err != nil {
			return domain.ProposedAction{}, err
		}
		evidence = append(evidence, decoded)
	}
	return domain.NewProposedAction(
		stored.Type,
		requestedAt,
		actor,
		delegation,
		target,
		parameters,
		payload,
		evidence,
	)
}

func decodeParameters(typ domain.ActionType, value json.RawMessage) (domain.ActionParameters, error) {
	switch typ {
	case domain.ActionExternalSend:
		var stored persistedExternalSendParameters
		if err := json.Unmarshal(value, &stored); err != nil {
			return nil, err
		}
		return domain.NewExternalSendParameters(stored.DestinationScope, stored.Recipients)
	case domain.ActionUpdateResourceAccess:
		var stored persistedUpdateResourceAccessParameters
		if err := json.Unmarshal(value, &stored); err != nil {
			return nil, err
		}
		principals := make([]domain.Principal, 0, len(stored.TargetPrincipals))
		for _, item := range stored.TargetPrincipals {
			principal, err := decodePrincipal(item)
			if err != nil {
				return nil, err
			}
			principals = append(principals, principal)
		}
		return domain.NewUpdateResourceAccessParameters(stored.CurrentScope, stored.RequestedScope, principals)
	case domain.ActionDelete:
		var stored persistedDeleteParameters
		if err := json.Unmarshal(value, &stored); err != nil {
			return nil, err
		}
		return domain.NewDeleteParameters(stored.DeleteMode, stored.Recoverable)
	default:
		return nil, fmt.Errorf("unsupported action type %q", typ)
	}
}

func decodePrincipal(value persistedPrincipal) (domain.Principal, error) {
	typ, err := domain.ParsePrincipalType(string(value.Type))
	if err != nil {
		return domain.Principal{}, err
	}
	return domain.NewPrincipal(typ, value.ID)
}

func decodeDecision(typ string, reasonsJSON, requiredActionsJSON []byte) (domain.Decision, error) {
	decisionType, err := domain.ParseDecisionType(typ)
	if err != nil {
		return domain.Decision{}, err
	}
	var reasonValues []string
	if err := json.Unmarshal(reasonsJSON, &reasonValues); err != nil {
		return domain.Decision{}, err
	}
	reasons := make([]domain.ReasonCode, 0, len(reasonValues))
	for _, value := range reasonValues {
		reason, err := domain.ParseReasonCode(value)
		if err != nil {
			return domain.Decision{}, err
		}
		reasons = append(reasons, reason)
	}
	var requiredActionValues []string
	if err := json.Unmarshal(requiredActionsJSON, &requiredActionValues); err != nil {
		return domain.Decision{}, err
	}
	requiredActions := make([]domain.RequiredAction, 0, len(requiredActionValues))
	for _, value := range requiredActionValues {
		typ, err := domain.ParseRequiredActionType(value)
		if err != nil {
			return domain.Decision{}, err
		}
		if typ == domain.RequiredActionRequireApproval {
			requiredActions = append(requiredActions, domain.NewRequireApprovalAction())
		}
	}
	if decisionType == domain.DecisionAllow {
		if len(reasons) != 0 || len(requiredActions) != 0 {
			return domain.Decision{}, fmt.Errorf("stored ALLOW has reasons or required actions")
		}
		return domain.NewAllowDecision(), nil
	}
	return domain.NewDenyDecision(reasons, requiredActions)
}

func validateStrings(values []string, label string) error {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("%w: %s cannot be empty", application.ErrInvalidInput, label)
		}
	}
	return nil
}
