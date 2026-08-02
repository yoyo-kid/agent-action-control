package domain

import "fmt"

// PayloadFacts contains policy-relevant payload metadata without raw content.
type PayloadFacts struct {
	digest         PayloadDigest
	classification []string
	sizeBytes      *int64
}

func NewPayloadFacts(digest PayloadDigest, classification []string, sizeBytes *int64) (PayloadFacts, error) {
	if !digest.Valid() {
		return PayloadFacts{}, ErrInvalidDigest
	}
	labels, err := normalizeStrings(classification, 32, 128)
	if err != nil {
		return PayloadFacts{}, fmt.Errorf("%w: invalid payload classification", ErrInvalidArgument)
	}
	if sizeBytes != nil && *sizeBytes < 0 {
		return PayloadFacts{}, fmt.Errorf("%w: payload size cannot be negative", ErrInvalidArgument)
	}
	return PayloadFacts{
		digest:         digest,
		classification: labels,
		sizeBytes:      cloneInt64(sizeBytes),
	}, nil
}

func (payload PayloadFacts) Digest() PayloadDigest { return payload.digest }
func (payload PayloadFacts) Classification() []string {
	return append([]string(nil), payload.classification...)
}
func (payload PayloadFacts) SizeBytes() *int64 { return cloneInt64(payload.sizeBytes) }
func (payload PayloadFacts) valid() bool {
	_, err := NewPayloadFacts(payload.digest, payload.classification, payload.sizeBytes)
	return err == nil
}
func (payload PayloadFacts) clone() PayloadFacts {
	payload.classification = append([]string(nil), payload.classification...)
	payload.sizeBytes = cloneInt64(payload.sizeBytes)
	return payload
}

func cloneInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
