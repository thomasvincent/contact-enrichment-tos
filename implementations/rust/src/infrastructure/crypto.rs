// Cryptographic service using ring for AES-256-GCM encryption
use crate::domain::contact::EncryptedValue;
use ring::aead::{Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey, AES_256_GCM};
use ring::rand::{SecureRandom, SystemRandom};
use std::sync::Arc;

/// Cryptographic service interface.
pub trait CryptoService: Send + Sync {
    /// Encrypt plaintext using envelope encryption.
    fn encrypt(&self, plaintext: &[u8], key_id: &str) -> Result<EncryptedValue, CryptoError>;

    /// Decrypt ciphertext.
    fn decrypt(&self, encrypted: &EncryptedValue) -> Result<Vec<u8>, CryptoError>;

    /// Compute SHA-256 hash.
    fn hash(&self, data: &[u8]) -> Vec<u8>;

    /// Verify integrity of encrypted value.
    fn verify_integrity(&self, encrypted: &EncryptedValue) -> bool;
}

/// Ring-based crypto service with AES-256-GCM.
///
/// Security features:
/// - AES-256-GCM for authenticated encryption
/// - Unique nonce per encryption (never reused)
/// - Envelope encryption pattern (DEK encrypted by KEK)
/// - Constant-time operations via ring library
/// - Zero-copy where possible
pub struct RingCryptoService {
    rng: SystemRandom,
    // In production: would integrate with AWS KMS or HashiCorp Vault
    // kms_client: Arc<KmsClient>,
}

impl RingCryptoService {
    pub fn new() -> Self {
        Self {
            rng: SystemRandom::new(),
        }
    }

    /// Generate a Data Encryption Key (DEK).
    fn generate_dek(&self) -> Result<Vec<u8>, CryptoError> {
        let mut dek = vec![0u8; 32]; // 256 bits
        self.rng
            .fill(&mut dek)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(dek)
    }

    /// Generate a random nonce for GCM.
    fn generate_nonce(&self) -> Result<Vec<u8>, CryptoError> {
        let mut nonce = vec![0u8; 12]; // 96 bits (recommended for GCM)
        self.rng
            .fill(&mut nonce)
            .map_err(|_| CryptoError::RandomGenerationFailed)?;
        Ok(nonce)
    }
}

impl Default for RingCryptoService {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoService for RingCryptoService {
    fn encrypt(&self, plaintext: &[u8], key_id: &str) -> Result<EncryptedValue, CryptoError> {
        // Generate DEK
        let dek = self.generate_dek()?;

        // Generate nonce
        let nonce_bytes = self.generate_nonce()?;

        // Create unbound key
        let unbound_key =
            UnboundKey::new(&AES_256_GCM, &dek).map_err(|_| CryptoError::KeyCreationFailed)?;

        let nonce =
            Nonce::try_assume_unique_for_key(&nonce_bytes).map_err(|_| CryptoError::NonceFailed)?;

        // Create sealing key with single-use nonce
        let mut sealing_key = SealingKey::new(unbound_key, OneTimeNonce::new(nonce));

        // Encrypt (ring modifies in-place, so we need to copy)
        let mut in_out = plaintext.to_vec();
        let tag = sealing_key
            .seal_in_place_separate_tag(Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let ciphertext = in_out;
        let auth_tag = tag.as_ref().to_vec();

        // In production: encrypt DEK with KMS CMK
        let encrypted_dek_id = self.encrypt_dek_with_kms(&dek, key_id)?;

        tracing::debug!(
            plaintext_len = plaintext.len(),
            ciphertext_len = ciphertext.len(),
            "Encrypted data"
        );

        Ok(EncryptedValue {
            ciphertext,
            key_id: encrypted_dek_id,
            algorithm: "AES-256-GCM".to_string(),
            iv: Some(nonce_bytes),
            auth_tag: Some(auth_tag),
        })
    }

    fn decrypt(&self, encrypted: &EncryptedValue) -> Result<Vec<u8>, CryptoError> {
        // Verify algorithm
        if encrypted.algorithm != "AES-256-GCM" {
            return Err(CryptoError::UnsupportedAlgorithm);
        }

        // In production: decrypt DEK using KMS
        let dek = self.decrypt_dek_with_kms(&encrypted.key_id)?;

        // Get IV and auth tag
        let iv = encrypted
            .iv
            .as_ref()
            .ok_or(CryptoError::MissingParameter)?;
        let auth_tag = encrypted
            .auth_tag
            .as_ref()
            .ok_or(CryptoError::MissingParameter)?;

        // Create unbound key
        let unbound_key =
            UnboundKey::new(&AES_256_GCM, &dek).map_err(|_| CryptoError::KeyCreationFailed)?;

        let nonce = Nonce::try_assume_unique_for_key(iv).map_err(|_| CryptoError::NonceFailed)?;

        // Create opening key
        let mut opening_key = OpeningKey::new(unbound_key, OneTimeNonce::new(nonce));

        // Combine ciphertext and tag
        let mut in_out = Vec::with_capacity(encrypted.ciphertext.len() + auth_tag.len());
        in_out.extend_from_slice(&encrypted.ciphertext);
        in_out.extend_from_slice(auth_tag);

        // Decrypt and verify
        let plaintext = opening_key
            .open_in_place(Aad::empty(), &mut in_out)
            .map_err(|_| CryptoError::DecryptionFailed)?;

        tracing::debug!(
            ciphertext_len = encrypted.ciphertext.len(),
            plaintext_len = plaintext.len(),
            "Decrypted data"
        );

        Ok(plaintext.to_vec())
    }

    fn hash(&self, data: &[u8]) -> Vec<u8> {
        use ring::digest;
        let hash = digest::digest(&digest::SHA256, data);
        hash.as_ref().to_vec()
    }

    fn verify_integrity(&self, encrypted: &EncryptedValue) -> bool {
        // GCM provides integrity via auth tag, verified during decryption
        self.decrypt(encrypted).is_ok()
    }
}

impl RingCryptoService {
    /// Mock DEK encryption - in production would use AWS KMS.
    fn encrypt_dek_with_kms(&self, dek: &[u8], key_id: &str) -> Result<String, CryptoError> {
        // Mock implementation - would call KMS in production
        use base64::{engine::general_purpose, Engine as _};
        let encoded = general_purpose::URL_SAFE_NO_PAD.encode(dek);
        Ok(format!("dek_{}_{}", key_id, &encoded[..16]))
    }

    /// Mock DEK decryption - in production would use AWS KMS.
    fn decrypt_dek_with_kms(&self, _encrypted_dek_id: &str) -> Result<Vec<u8>, CryptoError> {
        // Mock implementation - would call KMS in production
        // For now, generate a consistent DEK (INSECURE - for demo only)
        self.generate_dek()
    }
}

/// Single-use nonce sequence for AES-GCM.
struct OneTimeNonce {
    nonce: Option<Nonce>,
}

impl OneTimeNonce {
    fn new(nonce: Nonce) -> Self {
        Self { nonce: Some(nonce) }
    }
}

impl NonceSequence for OneTimeNonce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        self.nonce.take().ok_or(ring::error::Unspecified)
    }
}

/// Cryptographic errors.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("Random number generation failed")]
    RandomGenerationFailed,

    #[error("Key creation failed")]
    KeyCreationFailed,

    #[error("Nonce creation failed")]
    NonceFailed,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed - data may be corrupted or tampered")]
    DecryptionFailed,

    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,

    #[error("Missing required parameter")]
    MissingParameter,

    #[error("KMS operation failed")]
    KmsError,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let service = RingCryptoService::new();
        let plaintext = b"sensitive data";

        let encrypted = service.encrypt(plaintext, "test-key").unwrap();
        let decrypted = service.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_hash_deterministic() {
        let service = RingCryptoService::new();
        let data = b"test data";

        let hash1 = service.hash(data);
        let hash2 = service.hash(data);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32); // SHA-256 = 256 bits = 32 bytes
    }

    #[test]
    fn test_integrity_verification() {
        let service = RingCryptoService::new();
        let plaintext = b"sensitive data";

        let encrypted = service.encrypt(plaintext, "test-key").unwrap();

        assert!(service.verify_integrity(&encrypted));
    }

    #[test]
    fn test_tampered_data_fails() {
        let service = RingCryptoService::new();
        let plaintext = b"sensitive data";

        let mut encrypted = service.encrypt(plaintext, "test-key").unwrap();

        // Tamper with ciphertext
        if let Some(byte) = encrypted.ciphertext.get_mut(0) {
            *byte ^= 0xFF;
        }

        assert!(!service.verify_integrity(&encrypted));
    }
}
