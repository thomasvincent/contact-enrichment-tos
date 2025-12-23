"""Contact aggregate root - Python implementation."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import FrozenSet, Optional
from uuid import UUID, uuid4


class ConfidentialityLevel(Enum):
    """Confidentiality levels for MAC."""
    PUBLIC = 0
    INTERNAL = 1
    CONFIDENTIAL = 2
    RESTRICTED = 3


class IntegrityLevel(Enum):
    """Integrity levels for Biba model."""
    LOW = 0
    MEDIUM = 1
    HIGH = 2
    CRITICAL = 3


@dataclass(frozen=True)
class SecurityLabel:
    """Immutable security label for MAC enforcement."""
    confidentiality: ConfidentialityLevel
    integrity: IntegrityLevel
    compartments: FrozenSet[str] = field(default_factory=frozenset)
    handling_caveats: FrozenSet[str] = field(default_factory=frozenset)

    def dominates(self, other: "SecurityLabel") -> bool:
        """Check if this label can access data with other label."""
        return (
            self.confidentiality.value >= other.confidentiality.value
            and self.integrity.value >= other.integrity.value
            and self.compartments.issuperset(other.compartments)
        )

    @classmethod
    def confidential_pii(cls) -> "SecurityLabel":
        """Factory for confidential PII label."""
        return cls(
            confidentiality=ConfidentialityLevel.CONFIDENTIAL,
            integrity=IntegrityLevel.HIGH,
            compartments=frozenset(["PII"]),
            handling_caveats=frozenset(["ENCRYPT_AT_REST", "NO_CACHE"])
        )


@dataclass(frozen=True)
class EncryptedValue:
    """Encrypted value with metadata."""
    ciphertext: bytes
    key_id: str
    algorithm: str = "AES-256-GCM"
    iv: Optional[bytes] = None
    auth_tag: Optional[bytes] = None


class AttributeType(Enum):
    """Types of enriched attributes."""
    FULL_NAME = "full_name"
    JOB_TITLE = "job_title"
    COMPANY_NAME = "company_name"
    PHONE_WORK = "phone_work"
    LINKEDIN_URL = "linkedin_url"


class ConsentType(Enum):
    """Types of consent."""
    EXPLICIT_OPT_IN = "explicit_opt_in"
    LEGITIMATE_INTEREST = "legitimate_interest"


class LegalBasis(Enum):
    """Legal basis for processing."""
    GDPR_ART6_1A_CONSENT = "gdpr_art6_1a"
    GDPR_ART6_1F_LEGITIMATE_INTEREST = "gdpr_art6_1f"
    CCPA_NOTICE = "ccpa_notice"


@dataclass
class EnrichedAttribute:
    """Enriched attribute with temporal validity."""
    id: UUID
    attribute_type: AttributeType
    encrypted_value: EncryptedValue
    provenance_id: UUID
    confidence_score: float
    valid_from: datetime
    valid_until: Optional[datetime]
    security_label: SecurityLabel

    def supersede(self, superseded_at: datetime) -> None:
        """Mark this attribute as superseded."""
        if self.valid_until is not None:
            raise ValueError("Attribute already superseded")
        self.valid_until = superseded_at


@dataclass
class ConsentRecord:
    """Consent record for legal basis."""
    id: UUID
    consent_type: ConsentType
    legal_basis: LegalBasis
    purpose_codes: list[str]
    evidence_ref: Optional[str]
    granted_at: datetime
    revoked_at: Optional[datetime] = None

    def revoke(self, revoked_at: datetime) -> None:
        """Revoke this consent."""
        if self.revoked_at is not None:
            raise ValueError("Consent already revoked")
        self.revoked_at = revoked_at

    def is_active(self) -> bool:
        """Check if consent is active."""
        return self.revoked_at is None


@dataclass
class Contact:
    """
    Contact aggregate root.

    Invariants:
    - Only one current attribute per type
    - All attributes must have provenance
    - At least one active consent required
    - Security label dominates all attribute labels
    """
    id: UUID
    canonical_email: EncryptedValue
    canonical_email_hash: bytes
    full_name: Optional[EncryptedValue]
    security_label: SecurityLabel
    enriched_attributes: list[EnrichedAttribute] = field(default_factory=list)
    consent_records: list[ConsentRecord] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
    created_by: UUID = field(default_factory=uuid4)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    version: int = 1

    @classmethod
    def create(
        cls,
        canonical_email: EncryptedValue,
        email_hash: bytes,
        full_name: Optional[EncryptedValue],
        security_label: SecurityLabel,
        created_by: UUID,
    ) -> "Contact":
        """Factory method to create new contact."""
        return cls(
            id=uuid4(),
            canonical_email=canonical_email,
            canonical_email_hash=email_hash,
            full_name=full_name,
            security_label=security_label,
            created_by=created_by,
        )

    def add_enrichment(
        self,
        attribute_type: AttributeType,
        encrypted_value: EncryptedValue,
        provenance_id: UUID,
        confidence_score: float,
        attribute_label: SecurityLabel,
        enriched_by: UUID,
    ) -> None:
        """Add enrichment with temporal validity."""
        # Validate security label
        if not self.security_label.dominates(attribute_label):
            raise SecurityError("Attribute label exceeds contact label")

        # Validate consent
        if not self._has_valid_consent():
            raise ValueError("No valid consent for processing")

        # Supersede existing current attributes
        now = datetime.utcnow()
        for attr in self.enriched_attributes:
            if attr.attribute_type == attribute_type and attr.valid_until is None:
                attr.supersede(now)

        # Add new attribute
        new_attr = EnrichedAttribute(
            id=uuid4(),
            attribute_type=attribute_type,
            encrypted_value=encrypted_value,
            provenance_id=provenance_id,
            confidence_score=confidence_score,
            valid_from=now,
            valid_until=None,
            security_label=attribute_label,
        )

        self.enriched_attributes.append(new_attr)
        self.updated_at = now

    def record_consent(
        self,
        consent_type: ConsentType,
        legal_basis: LegalBasis,
        purpose_codes: list[str],
        evidence_ref: Optional[str] = None,
    ) -> ConsentRecord:
        """Record consent for processing."""
        record = ConsentRecord(
            id=uuid4(),
            consent_type=consent_type,
            legal_basis=legal_basis,
            purpose_codes=purpose_codes,
            evidence_ref=evidence_ref,
            granted_at=datetime.utcnow(),
        )
        self.consent_records.append(record)
        return record

    def get_current_attributes(self) -> list[EnrichedAttribute]:
        """Get currently valid attributes."""
        return [attr for attr in self.enriched_attributes if attr.valid_until is None]

    def _has_valid_consent(self) -> bool:
        """Check if any active consent exists."""
        return any(record.is_active() for record in self.consent_records)


class SecurityError(Exception):
    """Security-related error."""
    pass
