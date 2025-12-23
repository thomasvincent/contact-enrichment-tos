// Package domain contains domain models and business logic.
package domain

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

// ConfidentialityLevel represents MAC confidentiality classification.
type ConfidentialityLevel int

const (
	Public ConfidentialityLevel = iota
	Internal
	Confidential
	Restricted
)

// IntegrityLevel represents Biba integrity classification.
type IntegrityLevel int

const (
	Low IntegrityLevel = iota
	Medium
	High
	Critical
)

// SecurityLabel is an immutable value object for MAC enforcement.
type SecurityLabel struct {
	confidentiality ConfidentialityLevel
	integrity       IntegrityLevel
	compartments    map[string]struct{}
}

// NewSecurityLabel creates a new security label (immutable).
func NewSecurityLabel(
	conf ConfidentialityLevel,
	integ IntegrityLevel,
	compartments []string,
) SecurityLabel {
	comps := make(map[string]struct{}, len(compartments))
	for _, c := range compartments {
		comps[c] = struct{}{}
	}

	return SecurityLabel{
		confidentiality: conf,
		integrity:       integ,
		compartments:    comps,
	}
}

// Dominates checks if this label can access data with other label.
func (sl SecurityLabel) Dominates(other SecurityLabel) bool {
	if sl.confidentiality < other.confidentiality {
		return false
	}
	if sl.integrity < other.integrity {
		return false
	}

	// Check compartments (must be superset)
	for comp := range other.compartments {
		if _, has := sl.compartments[comp]; !has {
			return false
		}
	}

	return true
}

// ConfidentialPII creates a label for confidential PII.
func ConfidentialPII() SecurityLabel {
	return NewSecurityLabel(
		Confidential,
		High,
		[]string{"PII"},
	)
}

// EncryptedValue represents encrypted data with metadata.
type EncryptedValue struct {
	Ciphertext []byte
	KeyID      string
	Algorithm  string
	IV         []byte
	AuthTag    []byte
}

// AttributeType defines types of enriched attributes.
type AttributeType string

const (
	FullName    AttributeType = "full_name"
	JobTitle    AttributeType = "job_title"
	CompanyName AttributeType = "company_name"
)

// EnrichedAttribute represents an enriched data point.
type EnrichedAttribute struct {
	ID             uuid.UUID
	AttributeType  AttributeType
	EncryptedValue EncryptedValue
	ProvenanceID   uuid.UUID
	Confidence     float64
	ValidFrom      time.Time
	ValidUntil     *time.Time
	SecurityLabel  SecurityLabel
}

// Supersede marks this attribute as no longer current.
func (ea *EnrichedAttribute) Supersede(supersededAt time.Time) error {
	if ea.ValidUntil != nil {
		return errors.New("attribute already superseded")
	}
	ea.ValidUntil = &supersededAt
	return nil
}

// Contact is the aggregate root for contact enrichment.
type Contact struct {
	ID                  uuid.UUID
	CanonicalEmail      EncryptedValue
	CanonicalEmailHash  []byte
	FullName            *EncryptedValue
	SecurityLabel       SecurityLabel
	EnrichedAttributes  []EnrichedAttribute
	CreatedAt           time.Time
	CreatedBy           uuid.UUID
	UpdatedAt           time.Time
	Version             int64
}

// NewContact creates a new contact aggregate.
func NewContact(
	email EncryptedValue,
	emailHash []byte,
	fullName *EncryptedValue,
	label SecurityLabel,
	createdBy uuid.UUID,
) *Contact {
	now := time.Now()
	return &Contact{
		ID:                 uuid.New(),
		CanonicalEmail:     email,
		CanonicalEmailHash: emailHash,
		FullName:           fullName,
		SecurityLabel:      label,
		EnrichedAttributes: make([]EnrichedAttribute, 0),
		CreatedAt:          now,
		CreatedBy:          createdBy,
		UpdatedAt:          now,
		Version:            1,
	}
}

// AddEnrichment adds an enriched attribute with validation.
func (c *Contact) AddEnrichment(
	attrType AttributeType,
	value EncryptedValue,
	provenanceID uuid.UUID,
	confidence float64,
	attrLabel SecurityLabel,
) error {
	// Validate security label
	if !c.SecurityLabel.Dominates(attrLabel) {
		return errors.New("attribute security label exceeds contact label")
	}

	// Supersede existing current attributes of same type
	now := time.Now()
	for i := range c.EnrichedAttributes {
		attr := &c.EnrichedAttributes[i]
		if attr.AttributeType == attrType && attr.ValidUntil == nil {
			if err := attr.Supersede(now); err != nil {
				return err
			}
		}
	}

	// Add new attribute
	newAttr := EnrichedAttribute{
		ID:             uuid.New(),
		AttributeType:  attrType,
		EncryptedValue: value,
		ProvenanceID:   provenanceID,
		Confidence:     confidence,
		ValidFrom:      now,
		ValidUntil:     nil,
		SecurityLabel:  attrLabel,
	}

	c.EnrichedAttributes = append(c.EnrichedAttributes, newAttr)
	c.UpdatedAt = now

	return nil
}

// GetCurrentAttributes returns currently valid attributes.
func (c *Contact) GetCurrentAttributes() []EnrichedAttribute {
	current := make([]EnrichedAttribute, 0)
	for _, attr := range c.EnrichedAttributes {
		if attr.ValidUntil == nil {
			current = append(current, attr)
		}
	}
	return current
}
