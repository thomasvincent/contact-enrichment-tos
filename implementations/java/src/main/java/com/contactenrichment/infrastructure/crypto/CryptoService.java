package com.contactenrichment.infrastructure.crypto;

import com.contactenrichment.domain.model.EncryptedValue;
import com.contactenrichment.infrastructure.security.SecurityContext;

/**
 * Cryptographic service interface.
 *
 * <p>Implementations integrate with HSM/KMS for key management.
 *
 * @author Security Team
 * @since 1.0.0
 */
public interface CryptoService {

    /**
     * Encrypt data using envelope encryption.
     *
     * @param plaintext Data to encrypt
     * @param keyId Key identifier (e.g., "email-key", "name-key")
     * @return Encrypted value with metadata
     */
    EncryptedValue encrypt(byte[] plaintext, String keyId);

    /**
     * Decrypt data.
     *
     * @param encryptedValue Encrypted value
     * @return Decrypted plaintext bytes
     */
    byte[] decrypt(EncryptedValue encryptedValue);

    /**
     * Hash data (e.g., SHA-256) for lookups.
     */
    byte[] hash(byte[] data);

    /**
     * Verify integrity (GCM tag) where applicable.
     */
    boolean verifyIntegrity(EncryptedValue encryptedValue);
}
