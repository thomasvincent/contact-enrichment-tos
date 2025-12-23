package com.contactenrichment.domain.model;

import jakarta.persistence.Embeddable;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.owasp.encoder.Encode;

import java.io.Serializable;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * Security Label for Mandatory Access Control (MAC).
 *
 * <p>Implements Bell-LaPadula model for confidentiality and Biba model for integrity.
 * Immutable value object ensuring security classifications cannot be mutated.
 *
 * <p><strong>Security Considerations:</strong>
 * <ul>
 *   <li>Immutable by design - no setters after construction</li>
 *   <li>Defensive copying of compartment sets</li>
 *   <li>Validation in constructor prevents invalid states</li>
 *   <li>Uses enum types to prevent injection</li>
 * </ul>
 *
 * @author Security Team
 * @since 1.0.0
 */
@Embeddable
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED) // JPA requirement
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@EqualsAndHashCode
public final class SecurityLabel implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Confidentiality level following Bell-LaPadula model.
     * Higher values indicate more restrictive access.
     */
    @NotNull
    @Enumerated(EnumType.STRING)
    private ConfidentialityLevel confidentiality;

    /**
     * Integrity level following Biba model.
     * Higher values indicate more trustworthy data.
     */
    @NotNull
    @Enumerated(EnumType.STRING)
    private IntegrityLevel integrity;

    /**
     * Compartments for need-to-know access control.
     * Even with sufficient clearance, users must be granted specific compartments.
     *
     * <p><strong>Security:</strong> Stored as unmodifiable set to prevent tampering.
     */
    @jakarta.persistence.ElementCollection(fetch = jakarta.persistence.FetchType.EAGER)
    @jakarta.persistence.CollectionTable(
        name = "security_label_compartments",
        joinColumns = @jakarta.persistence.JoinColumn(name = "security_label_id")
    )
    @jakarta.persistence.Column(name = "compartment")
    private Set<String> compartments;

    /**
     * Handling caveats (e.g., "NO_FOREIGN", "NO_CACHE").
     *
     * <p><strong>Security:</strong> Stored as unmodifiable set.
     */
    @jakarta.persistence.ElementCollection(fetch = jakarta.persistence.FetchType.EAGER)
    @jakarta.persistence.CollectionTable(
        name = "security_label_caveats",
        joinColumns = @jakarta.persistence.JoinColumn(name = "security_label_id")
    )
    @jakarta.persistence.Column(name = "caveat")
    private Set<String> handlingCaveats;

    /**
     * Creates a new SecurityLabel with defensive copying of mutable collections.
     *
     * @param confidentiality Confidentiality level (required)
     * @param integrity Integrity level (required)
     * @param compartments Compartment set (nullable, defensively copied)
     * @param handlingCaveats Handling caveats (nullable, defensively copied)
     * @throws IllegalArgumentException if confidentiality or integrity is null
     */
    public SecurityLabel(
            ConfidentialityLevel confidentiality,
            IntegrityLevel integrity,
            Set<String> compartments,
            Set<String> handlingCaveats) {

        this.confidentiality = Objects.requireNonNull(
            confidentiality,
            "Confidentiality level must not be null"
        );
        this.integrity = Objects.requireNonNull(
            integrity,
            "Integrity level must not be null"
        );

        // Defensive copy to prevent external mutation
        this.compartments = compartments != null
            ? Set.copyOf(validateCompartments(compartments))
            : Set.of();

        this.handlingCaveats = handlingCaveats != null
            ? Set.copyOf(validateCaveats(handlingCaveats))
            : Set.of();
    }

    /**
     * Factory method for public data.
     *
     * @return Security label for publicly accessible data
     */
    public static SecurityLabel publicData() {
        return new SecurityLabel(
            ConfidentialityLevel.PUBLIC,
            IntegrityLevel.LOW,
            Set.of(),
            Set.of()
        );
    }

    /**
     * Factory method for internal data.
     *
     * @return Security label for internal-only data
     */
    public static SecurityLabel internalData() {
        return new SecurityLabel(
            ConfidentialityLevel.INTERNAL,
            IntegrityLevel.MEDIUM,
            Set.of(),
            Set.of()
        );
    }

    /**
     * Factory method for confidential PII.
     *
     * @return Security label for confidential personally identifiable information
     */
    public static SecurityLabel confidentialPii() {
        return new SecurityLabel(
            ConfidentialityLevel.CONFIDENTIAL,
            IntegrityLevel.HIGH,
            Set.of("PII"),
            Set.of("ENCRYPT_AT_REST", "NO_CACHE")
        );
    }

    /**
     * Factory method for restricted data.
     *
     * @return Security label for highly restricted data
     */
    public static SecurityLabel restrictedData() {
        return new SecurityLabel(
            ConfidentialityLevel.RESTRICTED,
            IntegrityLevel.CRITICAL,
            Set.of(),
            Set.of("NO_FOREIGN", "MFA_REQUIRED")
        );
    }

    /**
     * Check if this label dominates another (can access data with the other label).
     *
     * <p>Dominance criteria:
     * <ul>
     *   <li>This confidentiality level >= other's confidentiality level</li>
     *   <li>This integrity level >= other's integrity level</li>
     *   <li>This compartments superset of other's compartments</li>
     * </ul>
     *
     * @param other The label to check against
     * @return true if this label dominates the other
     */
    public boolean dominates(SecurityLabel other) {
        Objects.requireNonNull(other, "Other security label must not be null");

        return this.confidentiality.ordinal() >= other.confidentiality.ordinal()
            && this.integrity.ordinal() >= other.integrity.ordinal()
            && this.compartments.containsAll(other.compartments);
    }

    /**
     * Unmodifiable view of compartments.
     *
     * @return Unmodifiable set of compartments
     */
    public Set<String> getCompartments() {
        return Collections.unmodifiableSet(compartments);
    }

    /**
     * Unmodifiable view of handling caveats.
     *
     * @return Unmodifiable set of caveats
     */
    public Set<String> getHandlingCaveats() {
        return Collections.unmodifiableSet(handlingCaveats);
    }

    /**
     * Validates compartment names to prevent injection attacks.
     *
     * @param compartments Compartments to validate
     * @return Validated compartments
     * @throws IllegalArgumentException if any compartment is invalid
     */
    private Set<String> validateCompartments(Set<String> compartments) {
        compartments.forEach(c -> {
            if (c == null || c.isBlank()) {
                throw new IllegalArgumentException("Compartment cannot be null or blank");
            }
            // Alphanumeric and underscores only (prevent injection)
            if (!c.matches("^[A-Z0-9_]+$")) {
                throw new IllegalArgumentException(
                    "Invalid compartment name (must be uppercase alphanumeric + underscores): "
                        + Encode.forJava(c)
                );
            }
        });
        return compartments;
    }

    /**
     * Validates handling caveats to prevent injection attacks.
     *
     * @param caveats Caveats to validate
     * @return Validated caveats
     * @throws IllegalArgumentException if any caveat is invalid
     */
    private Set<String> validateCaveats(Set<String> caveats) {
        caveats.forEach(c -> {
            if (c == null || c.isBlank()) {
                throw new IllegalArgumentException("Caveat cannot be null or blank");
            }
            // Alphanumeric and underscores only
            if (!c.matches("^[A-Z0-9_]+$")) {
                throw new IllegalArgumentException(
                    "Invalid caveat name (must be uppercase alphanumeric + underscores): "
                        + Encode.forJava(c)
                );
            }
        });
        return caveats;
    }

    @Override
    public String toString() {
        // Sanitize output for logging (prevent log injection)
        return String.format(
            "SecurityLabel[confidentiality=%s, integrity=%s, compartments=%d, caveats=%d]",
            confidentiality,
            integrity,
            compartments.size(),
            handlingCaveats.size()
        );
    }

    /**
     * Confidentiality levels following Bell-LaPadula model.
     */
    public enum ConfidentialityLevel {
        /** Publicly accessible information. */
        PUBLIC(0),

        /** Internal use only within organization. */
        INTERNAL(1),

        /** Confidential, limited distribution. */
        CONFIDENTIAL(2),

        /** Highly restricted, top secret. */
        RESTRICTED(3);

        private final int level;

        ConfidentialityLevel(int level) {
            this.level = level;
        }

        public int getLevel() {
            return level;
        }
    }

    /**
     * Integrity levels following Biba model.
     */
    public enum IntegrityLevel {
        /** Low integrity, unverified data. */
        LOW(0),

        /** Medium integrity, some verification. */
        MEDIUM(1),

        /** High integrity, well-verified data. */
        HIGH(2),

        /** Critical integrity, cryptographically verified. */
        CRITICAL(3);

        private final int level;

        IntegrityLevel(int level) {
            this.level = level;
        }

        public int getLevel() {
            return level;
        }
    }
}
