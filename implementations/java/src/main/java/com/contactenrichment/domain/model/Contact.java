package com.contactenrichment.domain.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

/**
 * Contact Aggregate Root.
 *
 * <p>Represents the canonical identity of a contact with enriched attributes.
 * This is the main aggregate in the Contact Core bounded context.
 *
 * <p><strong>Invariants:</strong>
 * <ul>
 *   <li>Only one current (valid_until=NULL) attribute per type</li>
 *   <li>All attributes must have valid provenance references</li>
 *   <li>At least one active consent required for processing</li>
 *   <li>Security label must dominate all attribute labels</li>
 * </ul>
 *
 * <p><strong>Security:</strong>
 * <ul>
 *   <li>PII fields encrypted at rest</li>
 *   <li>Row-level security enforced via PostgreSQL RLS</li>
 *   <li>All mutations generate domain events for audit</li>
 * </ul>
 *
 * @author Security Team
 * @since 1.0.0
 */
@Entity
@Table(name = "contacts")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA requirement
public class Contact {

    @Id
    @Column(name = "id", nullable = false, updatable = false)
    private UUID id;

    /**
     * Encrypted primary email for identity.
     */
    @Embedded
    @AttributeOverrides({
        @AttributeOverride(name = "ciphertext", column = @Column(name = "canonical_email")),
        @AttributeOverride(name = "keyId", column = @Column(name = "email_key_id")),
        @AttributeOverride(name = "algorithm", column = @Column(name = "email_algorithm")),
        @AttributeOverride(name = "iv", column = @Column(name = "email_iv")),
        @AttributeOverride(name = "authTag", column = @Column(name = "email_auth_tag"))
    })
    private EncryptedValue canonicalEmail;

    /**
     * SHA-256 hash of email for lookups without decryption.
     */
    @Column(name = "canonical_email_hash", nullable = false, unique = true, length = 32)
    private byte[] canonicalEmailHash;

    /**
     * Encrypted full name (optional).
     */
    @Embedded
    @AttributeOverrides({
        @AttributeOverride(name = "ciphertext", column = @Column(name = "full_name")),
        @AttributeOverride(name = "keyId", column = @Column(name = "name_key_id")),
        @AttributeOverride(name = "algorithm", column = @Column(name = "name_algorithm")),
        @AttributeOverride(name = "iv", column = @Column(name = "name_iv")),
        @AttributeOverride(name = "authTag", column = @Column(name = "name_auth_tag"))
    })
    private EncryptedValue fullName;

    /**
     * Security label for Mandatory Access Control.
     */
    @Embedded
    @NotNull
    private SecurityLabel securityLabel;

    /**
     * Enriched attributes with temporal validity.
     */
    @OneToMany(mappedBy = "contact", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<EnrichedAttribute> enrichedAttributes = new ArrayList<>();

    /**
     * Consent records for legal processing basis.
     */
    @OneToMany(mappedBy = "contact", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ConsentRecord> consentRecords = new ArrayList<>();

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "created_by", nullable = false, updatable = false)
    private UUID createdBy;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @Version
    @Column(name = "version", nullable = false)
    private Long version;

    /**
     * Domain events emitted by this aggregate (not persisted).
     */
    @Transient
    private final List<DomainEvent> domainEvents = new ArrayList<>();

    /**
     * Private constructor for aggregate creation.
     */
    private Contact(
            UUID id,
            EncryptedValue canonicalEmail,
            byte[] canonicalEmailHash,
            EncryptedValue fullName,
            SecurityLabel securityLabel,
            UUID createdBy) {

        this.id = id;
        this.canonicalEmail = canonicalEmail;
        this.canonicalEmailHash = canonicalEmailHash;
        this.fullName = fullName;
        this.securityLabel = securityLabel;
        this.createdBy = createdBy;
        this.createdAt = Instant.now();
        this.updatedAt = Instant.now();
        // version is managed by JPA - leave it null for new entities
    }

    /**
     * Factory method to create a new Contact.
     *
     * @param id Contact ID (ULID)
     * @param canonicalEmail Encrypted email
     * @param emailHash SHA-256 hash of email
     * @param fullName Encrypted full name (optional)
     * @param securityLabel MAC security label
     * @param createdBy Principal creating the contact
     * @return New Contact instance
     */
    public static Contact create(
            UUID id,
            EncryptedValue canonicalEmail,
            byte[] emailHash,
            EncryptedValue fullName,
            SecurityLabel securityLabel,
            UUID createdBy) {

        Contact contact = new Contact(
            id,
            canonicalEmail,
            emailHash,
            fullName,
            securityLabel,
            createdBy
        );

        // Emit domain event
        contact.addDomainEvent(new ContactCreated(
            id,
            securityLabel,
            createdBy,
            Instant.now()
        ));

        return contact;
    }

    /**
     * Reconstitute Contact from persistence (no domain events emitted).
     * Used by repository when loading from database.
     *
     * @param id Contact ID
     * @param canonicalEmail Encrypted email
     * @param emailHash Email hash
     * @param fullName Encrypted full name (optional)
     * @param securityLabel Security label
     * @param createdAt Creation timestamp
     * @param createdBy Creator ID
     * @param updatedAt Last update timestamp
     * @param version Optimistic lock version
     * @return Reconstituted Contact instance
     */
    public static Contact reconstitute(
            UUID id,
            EncryptedValue canonicalEmail,
            byte[] emailHash,
            EncryptedValue fullName,
            SecurityLabel securityLabel,
            Instant createdAt,
            UUID createdBy,
            Instant updatedAt,
            Long version) {

        Contact contact = new Contact(
            id,
            canonicalEmail,
            emailHash,
            fullName,
            securityLabel,
            createdBy
        );

        // Override timestamps and version from persistence
        contact.createdAt = createdAt;
        contact.updatedAt = updatedAt;
        contact.version = version;

        // No domain events emitted for reconstitution
        return contact;
    }

    /**
     * Add an enriched attribute with temporal validity.
     *
     * @param attributeType Type of attribute
     * @param encryptedValue Encrypted value
     * @param provenanceId Link to provenance ledger
     * @param confidenceScore Confidence in accuracy (0.0-1.0)
     * @param attributeLabel Security label for this attribute
     * @param enrichedBy Principal performing enrichment
     * @throws SecurityException if attribute label exceeds contact label
     * @throws IllegalStateException if no valid consent exists
     */
    public void addEnrichment(
            AttributeType attributeType,
            EncryptedValue encryptedValue,
            UUID provenanceId,
            Double confidenceScore,
            SecurityLabel attributeLabel,
            UUID enrichedBy) {

        // Invariant: Contact label must dominate attribute label
        if (!this.securityLabel.dominates(attributeLabel)) {
            throw new SecurityException(
                "Attribute security label exceeds contact security label"
            );
        }

        // Invariant: Must have valid consent
        if (!hasValidConsent()) {
            throw new IllegalStateException("No valid consent for processing");
        }

        // Supersede any existing current attribute of same type
        Instant now = Instant.now();
        enrichedAttributes.stream()
            .filter(attr -> attr.getAttributeType() == attributeType)
            .filter(attr -> attr.getValidUntil() == null) // Current attributes
            .forEach(attr -> attr.supersede(now));

        // Create new attribute
        EnrichedAttribute newAttribute = new EnrichedAttribute(
            UUID.randomUUID(),
            this,
            attributeType,
            encryptedValue,
            provenanceId,
            confidenceScore,
            now,
            null, // valid_until is NULL for current
            attributeLabel
        );

        enrichedAttributes.add(newAttribute);
        this.updatedAt = now;

        // Emit domain event
        addDomainEvent(new ContactEnriched(
            this.id,
            attributeType,
            provenanceId,
            enrichedBy,
            now
        ));
    }

    /**
     * Record consent for data processing.
     *
     * @param consentType Type of consent
     * @param legalBasis Legal basis (GDPR Article, CCPA, etc.)
     * @param purposeCodes Processing purposes
     * @param evidenceRef Link to consent capture evidence
     * @return Created consent record
     */
    public ConsentRecord recordConsent(
            ConsentType consentType,
            LegalBasis legalBasis,
            List<String> purposeCodes,
            String evidenceRef) {

        ConsentRecord record = new ConsentRecord(
            UUID.randomUUID(),
            this,
            consentType,
            legalBasis,
            purposeCodes,
            evidenceRef,
            Instant.now(),
            null // Not revoked
        );

        consentRecords.add(record);
        this.updatedAt = Instant.now();

        addDomainEvent(new ConsentGranted(
            this.id,
            record.getId(),
            legalBasis,
            Instant.now()
        ));

        return record;
    }

    /**
     * Revoke a consent record.
     *
     * @param consentId ID of consent to revoke
     * @throws IllegalArgumentException if consent not found
     */
    public void revokeConsent(UUID consentId) {
        ConsentRecord record = consentRecords.stream()
            .filter(c -> c.getId().equals(consentId))
            .findFirst()
            .orElseThrow(() -> new IllegalArgumentException(
                "Consent record not found: " + consentId
            ));

        Instant now = Instant.now();
        record.revoke(now);
        this.updatedAt = now;

        addDomainEvent(new ConsentRevoked(
            this.id,
            consentId,
            now
        ));
    }

    /**
     * Get all currently valid attributes.
     *
     * @return Unmodifiable list of current attributes
     */
    public List<EnrichedAttribute> getCurrentAttributes() {
        return enrichedAttributes.stream()
            .filter(attr -> attr.getValidUntil() == null)
            .toList();
    }

    /**
     * Get attribute history for a specific type.
     *
     * @param attributeType Type to query
     * @return Unmodifiable list of attributes, newest first
     */
    public List<EnrichedAttribute> getAttributeHistory(AttributeType attributeType) {
        return enrichedAttributes.stream()
            .filter(attr -> attr.getAttributeType() == attributeType)
            .sorted((a, b) -> b.getValidFrom().compareTo(a.getValidFrom()))
            .toList();
    }

    /**
     * Check if contact has any active consent.
     *
     * @return true if at least one active consent exists
     */
    private boolean hasValidConsent() {
        return consentRecords.stream()
            .anyMatch(c -> c.getRevokedAt() == null);
    }

    /**
     * Collect and clear pending domain events.
     *
     * @return List of domain events
     */
    public List<DomainEvent> collectDomainEvents() {
        List<DomainEvent> events = new ArrayList<>(domainEvents);
        domainEvents.clear();
        return Collections.unmodifiableList(events);
    }

    /**
     * Add domain event to pending list.
     */
    private void addDomainEvent(DomainEvent event) {
        domainEvents.add(event);
    }

    /**
     * Domain event base class.
     */
    public interface DomainEvent {
        UUID getAggregateId();
        Instant getOccurredAt();
    }

    public record ContactCreated(
        UUID aggregateId,
        SecurityLabel securityLabel,
        UUID createdBy,
        Instant occurredAt
    ) implements DomainEvent {
        @Override
        public UUID getAggregateId() {
            return aggregateId;
        }

        @Override
        public Instant getOccurredAt() {
            return occurredAt;
        }
    }

    public record ContactEnriched(
        UUID aggregateId,
        AttributeType attributeType,
        UUID provenanceId,
        UUID enrichedBy,
        Instant occurredAt
    ) implements DomainEvent {
        @Override
        public UUID getAggregateId() {
            return aggregateId;
        }

        @Override
        public Instant getOccurredAt() {
            return occurredAt;
        }
    }

    public record ConsentGranted(
        UUID aggregateId,
        UUID consentId,
        LegalBasis legalBasis,
        Instant occurredAt
    ) implements DomainEvent {
        @Override
        public UUID getAggregateId() {
            return aggregateId;
        }

        @Override
        public Instant getOccurredAt() {
            return occurredAt;
        }
    }

    public record ConsentRevoked(
        UUID aggregateId,
        UUID consentId,
        Instant occurredAt
    ) implements DomainEvent {
        @Override
        public UUID getAggregateId() {
            return aggregateId;
        }

        @Override
        public Instant getOccurredAt() {
            return occurredAt;
        }
    }
}

