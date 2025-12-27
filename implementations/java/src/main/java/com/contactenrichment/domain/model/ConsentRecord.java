package com.contactenrichment.domain.model;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@Entity
@Table(name = "consent_records")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ConsentRecord {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "contact_id", nullable = false)
    private Contact contact;

    @Enumerated(EnumType.STRING)
    @Column(name = "consent_type", nullable = false)
    private ConsentType consentType;

    @Enumerated(EnumType.STRING)
    @Column(name = "legal_basis", nullable = false)
    private LegalBasis legalBasis;

    @ElementCollection
    @CollectionTable(name = "consent_purpose_codes", joinColumns = @JoinColumn(name = "consent_id"))
    @Column(name = "purpose_code")
    private List<String> purposeCodes;

    @Column(name = "evidence_ref")
    private String evidenceRef;

    @Column(name = "granted_at", nullable = false)
    private Instant grantedAt;

    @Column(name = "revoked_at")
    private Instant revokedAt;

    public ConsentRecord(
            UUID id,
            Contact contact,
            ConsentType consentType,
            LegalBasis legalBasis,
            List<String> purposeCodes,
            String evidenceRef,
            Instant grantedAt,
            Instant revokedAt) {

        this.id = id;
        this.contact = contact;
        this.consentType = consentType;
        this.legalBasis = legalBasis;
        this.purposeCodes = new ArrayList<>(purposeCodes);
        this.evidenceRef = evidenceRef;
        this.grantedAt = grantedAt;
        this.revokedAt = revokedAt;
    }

    public void revoke(Instant revokedAt) {
        if (this.revokedAt != null) {
            throw new IllegalStateException("Consent already revoked");
        }
        this.revokedAt = revokedAt;
    }

    public boolean isActive() {
        return revokedAt == null;
    }
}