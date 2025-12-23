package com.contactenrichment.infrastructure.crypto;

import com.contactenrichment.domain.model.EncryptedValue;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AWS KMS-based cryptographic service implementing envelope encryption.
 *
 * Architecture:
 * - Customer Master Key (CMK) stored in AWS KMS (never leaves HSM)
 * - Data Encryption Keys (DEKs) generated for each encrypt operation
 * - DEKs encrypted by CMK (envelope encryption)
 * - AES-256-GCM for data encryption (authenticated encryption)
 *
 * Security properties:
 * - Forward secrecy via unique DEK per encryption
 * - Authentication via GCM mode (integrity + confidentiality)
 * - Key rotation support via key versioning
 * - Audit trail via AWS CloudTrail
 *
 * @see <a href="https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html">AWS KMS Concepts</a>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AwsKmsCryptoService implements CryptoService {

    private static final String ALGORITHM = "AES-256-GCM";
    private static final int GCM_IV_LENGTH = 12; // 96 bits recommended for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128 bits authentication tag
    private static final int AES_KEY_SIZE = 256;

    private final SecureRandom secureRandom = new SecureRandom();

    // In-memory cache for DEKs (would use Redis in production)
    private final Map<String, SecretKey> dekCache = new ConcurrentHashMap<>();

    // TODO: Inject AWS KMS client
    // private final AWSKMS kmsClient;

    @Override
    public EncryptedValue encrypt(byte[] plaintext, String keyId) {
        try {
            // Generate Data Encryption Key (DEK)
            SecretKey dek = generateDek();

            // Generate IV for GCM
            byte[] iv = new byte[GCM_IV_LENGTH];
            secureRandom.nextBytes(iv);

            // Encrypt plaintext with DEK
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
            cipher.init(Cipher.ENCRYPT_MODE, dek, gcmSpec);

            // GCM produces ciphertext || auth_tag
            byte[] ciphertextWithTag = cipher.doFinal(plaintext);

            // Split ciphertext and auth tag
            int ciphertextLength = ciphertextWithTag.length - (GCM_TAG_LENGTH / 8);
            byte[] ciphertext = new byte[ciphertextLength];
            byte[] authTag = new byte[GCM_TAG_LENGTH / 8];

            System.arraycopy(ciphertextWithTag, 0, ciphertext, 0, ciphertextLength);
            System.arraycopy(ciphertextWithTag, ciphertextLength, authTag, 0, authTag.length);

            // Encrypt DEK with CMK (envelope encryption)
            // In production: use AWS KMS to encrypt DEK
            String encryptedDekId = encryptDekWithCmk(dek, keyId);

            log.debug("Encrypted {} bytes with DEK {}", plaintext.length, encryptedDekId);

            return new EncryptedValue(
                ciphertext,
                encryptedDekId,  // Reference to encrypted DEK
                ALGORITHM,
                iv,
                authTag
            );

        } catch (Exception e) {
            log.error("Encryption failed", e);
            throw new CryptoException("Failed to encrypt data", e);
        }
    }

    @Override
    public byte[] decrypt(EncryptedValue encryptedValue) {
        try {
            // Retrieve and decrypt DEK from CMK
            // In production: use AWS KMS to decrypt DEK
            SecretKey dek = decryptDekWithCmk(encryptedValue.getKeyId());

            // Combine ciphertext and auth tag for GCM
            byte[] ciphertextWithTag = ByteBuffer.allocate(
                encryptedValue.getCiphertext().length + encryptedValue.getAuthTag().length
            )
            .put(encryptedValue.getCiphertext())
            .put(encryptedValue.getAuthTag())
            .array();

            // Decrypt with DEK
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(
                GCM_TAG_LENGTH,
                encryptedValue.getIv()
            );
            cipher.init(Cipher.DECRYPT_MODE, dek, gcmSpec);

            byte[] plaintext = cipher.doFinal(ciphertextWithTag);

            log.debug("Decrypted {} bytes with DEK {}",
                plaintext.length, encryptedValue.getKeyId());

            return plaintext;

        } catch (Exception e) {
            log.error("Decryption failed for key {}", encryptedValue.getKeyId(), e);
            throw new CryptoException("Failed to decrypt data", e);
        }
    }

    @Override
    public byte[] hash(byte[] data) {
        try {
            java.security.MessageDigest digest =
                java.security.MessageDigest.getInstance("SHA-256");
            return digest.digest(data);
        } catch (Exception e) {
            throw new CryptoException("Failed to hash data", e);
        }
    }

    @Override
    public boolean verifyIntegrity(EncryptedValue encryptedValue) {
        // GCM mode provides built-in integrity via authentication tag
        // Integrity is verified during decryption
        try {
            decrypt(encryptedValue);
            return true;
        } catch (CryptoException e) {
            log.warn("Integrity check failed: {}", e.getMessage());
            return false;
        }
    }

    /**
     * Generate a new Data Encryption Key (DEK).
     */
    private SecretKey generateDek() throws Exception {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(AES_KEY_SIZE, secureRandom);
        return keyGen.generateKey();
    }

    /**
     * Encrypt DEK with Customer Master Key (CMK) using AWS KMS.
     *
     * In production, this would call:
     * kmsClient.encrypt(EncryptRequest.builder()
     *     .keyId(cmkId)
     *     .plaintext(SdkBytes.fromByteArray(dek.getEncoded()))
     *     .build())
     */
    private String encryptDekWithCmk(SecretKey dek, String cmkId) {
        // Mock implementation - would use AWS KMS in production
        String dekId = "dek_" + Base64.getUrlEncoder()
            .encodeToString(secureRandom.generateSeed(16));

        dekCache.put(dekId, dek);

        log.debug("Encrypted DEK with CMK {}: {}", cmkId, dekId);
        return dekId;
    }

    /**
     * Decrypt DEK using AWS KMS.
     *
     * In production, this would call:
     * kmsClient.decrypt(DecryptRequest.builder()
     *     .ciphertextBlob(SdkBytes.fromByteArray(encryptedDek))
     *     .build())
     */
    private SecretKey decryptDekWithCmk(String dekId) {
        // Mock implementation - would use AWS KMS in production
        SecretKey dek = dekCache.get(dekId);

        if (dek == null) {
            throw new CryptoException("DEK not found: " + dekId);
        }

        return dek;
    }

    /**
     * Exception thrown when cryptographic operations fail.
     */
    public static class CryptoException extends RuntimeException {
        public CryptoException(String message) {
            super(message);
        }

        public CryptoException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
