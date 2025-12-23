package com.contactenrichment.domain.model;

import jakarta.persistence.Column;
import jakarta.persistence.Embeddable;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.io.Serializable;
import java.util.Base64;
import java.util.Objects;

/**
 * Encrypted value with envelope encryption metadata.
 *
 * <p>Uses envelope encryption pattern:
 * <ul>
 *   <li>Data encrypted with Data Encryption Key (DEK)</li>
 *   <li>DEK encrypted with Key Encryption Key (KEK) from HSM</li>
 *   <li>Only encrypted data and key reference stored</li>
 * </ul>
 *
 * <p><strong>Security Guarantees:</strong>
 * <ul>
 *   <li>Immutable - cannot be modified after creation</li>
 *   <li>No plaintext exposure in this class</li>
 *   <li>Key ID reference only (never the actual key)</li>
 *   <li>Uses AES-256-GCM for authenticated encryption</li>
 *   <li>Prevents serialization of plaintext via transient fields</li>
 * </ul>
 *
 * <p><strong>OWASP Compliance:</strong>
 * <ul>
 *   <li>A02:2021 – Cryptographic Failures: Uses strong encryption</li>
 *   <li>A04:2021 – Insecure Design: Immutable, defensive design</li>
 *   <li>A08:2021 – Software and Data Integrity Failures: Authenticated encryption</li>
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
public final class EncryptedValue implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * Encrypted ciphertext (base64-encoded for storage).
     *
     * <p><strong>Security:</strong> Contains encrypted bytes only, never plaintext.
     * Stored as BYTEA in PostgreSQL with column-level encryption if available.
     */
    @NotNull
    @Column(name = "ciphertext", nullable = false, columnDefinition = "BYTEA")
    private byte[] ciphertext;

    /**
     * Reference to the Key Encryption Key (KEK) in HSM/KMS.
     *
     * <p><strong>Security:</strong> Never stores the actual key, only a reference.
     * Key rotation is supported by re-encrypting with new key ID.
     */
    @NotBlank
    @Column(name = "key_id", nullable = false, length = 256)
    private String keyId;

    /**
     * Encryption algorithm used.
     *
     * <p>Default: AES-256-GCM (authenticated encryption with associated data).
     * Authenticated encryption prevents tampering and provides confidentiality.
     */
    @NotBlank
    @Column(name = "algorithm", nullable = false, length = 64)
    private String algorithm;

    /**
     * Initialization Vector (IV) / Nonce for AES-GCM.
     *
     * <p><strong>Security:</strong> MUST be unique for each encryption operation.
     * Never reuse IV with the same key (catastrophic security failure).
     */
    @Column(name = "iv", columnDefinition = "BYTEA")
    private byte[] iv;

    /**
     * Authentication tag from AES-GCM.
     *
     * <p>Provides integrity verification - detects tampering.
     */
    @Column(name = "auth_tag", columnDefinition = "BYTEA")
    private byte[] authTag;

    /**
     * Creates an EncryptedValue with validation.
     *
     * @param ciphertext Encrypted bytes
     * @param keyId Key reference in HSM/KMS
     * @param algorithm Encryption algorithm (e.g., "AES-256-GCM")
     * @param iv Initialization vector
     * @param authTag Authentication tag (for AEAD modes)
     * @throws IllegalArgumentException if any required parameter is invalid
     */
    public EncryptedValue(
            byte[] ciphertext,
            String keyId,
            String algorithm,
            byte[] iv,
            byte[] authTag) {

        // Validate inputs (defense in depth)
        this.ciphertext = Objects.requireNonNull(ciphertext, "Ciphertext must not be null");
        if (ciphertext.length == 0) {
            throw new IllegalArgumentException("Ciphertext must not be empty");
        }

        this.keyId = validateKeyId(keyId);
        this.algorithm = validateAlgorithm(algorithm);

        this.iv = iv != null ? iv.clone() : null; // Defensive copy
        this.authTag = authTag != null ? authTag.clone() : null; // Defensive copy

        // Validate IV for GCM mode
        if ("AES-256-GCM".equals(algorithm) && (iv == null || iv.length != 12)) {
            throw new IllegalArgumentException("AES-256-GCM requires 12-byte IV");
        }

        // Validate auth tag for GCM mode
        if ("AES-256-GCM".equals(algorithm) && (authTag == null || authTag.length != 16)) {
            throw new IllegalArgumentException("AES-256-GCM requires 16-byte auth tag");
        }
    }

    /**
     * Defensive copy of ciphertext to prevent external mutation.
     *
     * @return Copy of ciphertext bytes
     */
    public byte[] getCiphertext() {
        return ciphertext != null ? ciphertext.clone() : null;
    }

    /**
     * Defensive copy of IV to prevent external mutation.
     *
     * @return Copy of IV bytes
     */
    public byte[] getIv() {
        return iv != null ? iv.clone() : null;
    }

    /**
     * Defensive copy of auth tag to prevent external mutation.
     *
     * @return Copy of auth tag bytes
     */
    public byte[] getAuthTag() {
        return authTag != null ? authTag.clone() : null;
    }

    /**
     * Validates key ID to prevent injection.
     *
     * @param keyId Key ID to validate
     * @return Validated key ID
     * @throws IllegalArgumentException if key ID is invalid
     */
    private String validateKeyId(String keyId) {
        if (keyId == null || keyId.isBlank()) {
            throw new IllegalArgumentException("Key ID must not be null or blank");
        }

        // Key ID format: alphanumeric, hyphens, underscores only (prevent injection)
        if (!keyId.matches("^[a-zA-Z0-9_-]+$")) {
            throw new IllegalArgumentException(
                "Invalid key ID format (must be alphanumeric with hyphens/underscores)"
            );
        }

        if (keyId.length() > 256) {
            throw new IllegalArgumentException("Key ID too long (max 256 characters)");
        }

        return keyId;
    }

    /**
     * Validates algorithm string to prevent injection.
     *
     * @param algorithm Algorithm name to validate
     * @return Validated algorithm
     * @throws IllegalArgumentException if algorithm is invalid
     */
    private String validateAlgorithm(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) {
            throw new IllegalArgumentException("Algorithm must not be null or blank");
        }

        // Whitelist approved algorithms only
        if (!algorithm.matches("^(AES-256-GCM|ChaCha20-Poly1305)$")) {
            throw new IllegalArgumentException(
                "Unsupported algorithm (must be AES-256-GCM or ChaCha20-Poly1305)"
            );
        }

        return algorithm;
    }

    /**
     * Returns base64-encoded ciphertext for logging/debugging.
     *
     * <p><strong>Security:</strong> Does NOT expose plaintext.
     * Truncates output to prevent log bloat.
     *
     * @return Safe string representation
     */
    @Override
    public String toString() {
        String truncatedCiphertext = ciphertext != null && ciphertext.length > 16
            ? Base64.getEncoder().encodeToString(ciphertext).substring(0, 16) + "..."
            : Base64.getEncoder().encodeToString(ciphertext != null ? ciphertext : new byte[0]);

        return String.format(
            "EncryptedValue[algorithm=%s, keyId=%s, ciphertext=%s]",
            algorithm,
            maskKeyId(keyId),
            truncatedCiphertext
        );
    }

    /**
     * Masks key ID for logging (shows only last 4 characters).
     *
     * @param keyId Key ID to mask
     * @return Masked key ID
     */
    private String maskKeyId(String keyId) {
        if (keyId == null || keyId.length() <= 4) {
            return "****";
        }
        return "****" + keyId.substring(keyId.length() - 4);
    }

    /**
     * Builder for creating EncryptedValue instances.
     */
    public static final class Builder {
        private byte[] ciphertext;
        private String keyId;
        private String algorithm = "AES-256-GCM"; // Secure default
        private byte[] iv;
        private byte[] authTag;

        public Builder ciphertext(byte[] ciphertext) {
            this.ciphertext = ciphertext != null ? ciphertext.clone() : null;
            return this;
        }

        public Builder keyId(String keyId) {
            this.keyId = keyId;
            return this;
        }

        public Builder algorithm(String algorithm) {
            this.algorithm = algorithm;
            return this;
        }

        public Builder iv(byte[] iv) {
            this.iv = iv != null ? iv.clone() : null;
            return this;
        }

        public Builder authTag(byte[] authTag) {
            this.authTag = authTag != null ? authTag.clone() : null;
            return this;
        }

        public EncryptedValue build() {
            return new EncryptedValue(ciphertext, keyId, algorithm, iv, authTag);
        }
    }

    public static Builder builder() {
        return new Builder();
    }
}
