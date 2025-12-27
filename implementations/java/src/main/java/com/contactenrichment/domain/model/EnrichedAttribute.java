package com.contactenrichment.domain.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "enriched_attributes")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class EnrichedAttribute {

    @Id
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "contact_id", nullable = false)
    private Contact contact;

    @Enumerated(EnumType.STRING)
    @Column(name = "attribute_type", nullable = false, length = 50)
    private AttributeType attributeType;

    @Embedded
    private EncryptedValue encryptedValue;

    @Column(name = "provenance_id", nullable = false)
    private UUID provenanceId;

    @Column(name = "confidence_score")
    private Double confidenceScore;

    @Column(name = "valid_from", nullable = false)
    private Instant validFrom;

    @Column(name = "valid_until")
    private Instant validUntil;

    @Embedded
    private SecurityLabel securityLabel;

    public EnrichedAttribute(
            UUID id,
            Contact contact,
            AttributeType attributeType,
            EncryptedValue encryptedValue,
            UUID provenanceId,
            Double confidenceScore,
            Instant validFrom,
            Instant validUntil,
            SecurityLabel securityLabel) {

        this.id = id;
        this.contact = contact;
        this.attributeType = attributeType;
        this.encryptedValue = encryptedValue;
        this.provenanceId = provenanceId;
        this.confidenceScore = confidenceScore;
        this.validFrom = validFrom;
        this.validUntil = validUntil;
        this.securityLabel = securityLabel;
    }

    public void supersede(Instant supersededAt) {
        if (this.validUntil != null) {
            throw new IllegalStateException("Attribute already superseded");
        }
        this.validUntil = supersededAt;
    }
}