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
     * @param context Security context
     * @return Encrypted value with metadata
     */
    EncryptedValue encrypt(byte[] plaintext, SecurityContext context);

    /**
     * Decrypt data after authorization check.
     *
     * @param encryptedValue Encrypted value
     * @param context Security context
     * @return Decrypted plaintext
     */
    String decrypt(EncryptedValue encryptedValue, SecurityContext context);

    /**
     * Generate cryptographically secure random bytes.
     *
     * @param numBytes Number of bytes
     * @return Random bytes
     */
    byte[] generateRandom(int numBytes);
}
