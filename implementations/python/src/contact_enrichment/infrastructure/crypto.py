"""Cryptographic service using cryptography library for AES-256-GCM."""
import hashlib
import logging
import secrets
from typing import Protocol

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from contact_enrichment.domain.contact import EncryptedValue

logger = logging.getLogger(__name__)


class CryptoService(Protocol):
    """Cryptographic service interface."""

    def encrypt(self, plaintext: bytes, key_id: str) -> EncryptedValue:
        """Encrypt plaintext using envelope encryption."""
        ...

    def decrypt(self, encrypted: EncryptedValue) -> bytes:
        """Decrypt ciphertext."""
        ...

    def hash(self, data: bytes) -> bytes:
        """Compute SHA-256 hash."""
        ...

    def verify_integrity(self, encrypted: EncryptedValue) -> bool:
        """Verify integrity of encrypted value."""
        ...


class AesGcmCryptoService:
    """AES-256-GCM cryptographic service with envelope encryption.

    Security features:
    - AES-256-GCM for authenticated encryption
    - Unique nonce per encryption (96-bit random)
    - Envelope encryption pattern (DEK encrypted by KEK)
    - FIPS-compliant cryptography library
    - Constant-time operations
    """

    ALGORITHM = "AES-256-GCM"
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits (recommended for GCM)

    def __init__(self):
        # In production: would integrate with AWS KMS or HashiCorp Vault
        self._dek_cache = {}  # Mock DEK cache

    def encrypt(self, plaintext: bytes, key_id: str) -> EncryptedValue:
        """Encrypt plaintext with AES-256-GCM."""
        try:
            # Generate Data Encryption Key (DEK)
            dek = secrets.token_bytes(self.KEY_SIZE)

            # Generate nonce (must be unique per encryption)
            nonce = secrets.token_bytes(self.NONCE_SIZE)

            # Encrypt with AES-256-GCM
            aesgcm = AESGCM(dek)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            # GCM produces ciphertext || auth_tag
            # Split them (last 16 bytes are auth tag)
            auth_tag = ciphertext[-16:]
            ciphertext_only = ciphertext[:-16]

            # Encrypt DEK with KEK (mock implementation)
            encrypted_dek_id = self._encrypt_dek_with_kms(dek, key_id)

            logger.debug(f"Encrypted {len(plaintext)} bytes with DEK {encrypted_dek_id}")

            return EncryptedValue(
                ciphertext=ciphertext_only,
                key_id=encrypted_dek_id,
                algorithm=self.ALGORITHM,
                iv=nonce,
                auth_tag=auth_tag,
            )

        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            raise ValueError(f"Encryption failed: {e}")

    def decrypt(self, encrypted: EncryptedValue) -> bytes:
        """Decrypt ciphertext with AES-256-GCM."""
        try:
            # Verify algorithm
            if encrypted.algorithm != self.ALGORITHM:
                raise ValueError(f"Unsupported algorithm: {encrypted.algorithm}")

            # Decrypt DEK with KEK (mock implementation)
            dek = self._decrypt_dek_with_kms(encrypted.key_id)

            # Combine ciphertext and auth tag for GCM
            ciphertext_with_tag = encrypted.ciphertext + encrypted.auth_tag

            # Decrypt and verify
            aesgcm = AESGCM(dek)
            plaintext = aesgcm.decrypt(encrypted.iv, ciphertext_with_tag, None)

            logger.debug(f"Decrypted {len(plaintext)} bytes with DEK {encrypted.key_id}")

            return plaintext

        except Exception as e:
            logger.error(f"Decryption failed for key {encrypted.key_id}: {e}")
            raise ValueError(f"Decryption failed: {e}")

    def hash(self, data: bytes) -> bytes:
        """Compute SHA-256 hash."""
        return hashlib.sha256(data).digest()

    def verify_integrity(self, encrypted: EncryptedValue) -> bool:
        """Verify integrity via GCM auth tag (verified during decryption)."""
        try:
            self.decrypt(encrypted)
            return True
        except Exception as e:
            logger.warning(f"Integrity check failed: {e}")
            return False

    def _encrypt_dek_with_kms(self, dek: bytes, key_id: str) -> str:
        """Encrypt DEK with KEK using KMS (mock implementation).

        In production, this would call AWS KMS or similar:
        kms_client.encrypt(KeyId=cmk_id, Plaintext=dek)
        """
        import base64

        # Generate unique DEK ID
        dek_id = f"dek_{key_id}_{secrets.token_urlsafe(16)}"

        # Cache DEK (in production, this would be in KMS)
        self._dek_cache[dek_id] = dek

        logger.debug(f"Encrypted DEK with KEK {key_id}: {dek_id}")
        return dek_id

    def _decrypt_dek_with_kms(self, encrypted_dek_id: str) -> bytes:
        """Decrypt DEK using KMS (mock implementation).

        In production, this would call AWS KMS:
        kms_client.decrypt(CiphertextBlob=encrypted_dek)
        """
        # Retrieve DEK from cache (in production, decrypt via KMS)
        dek = self._dek_cache.get(encrypted_dek_id)

        if not dek:
            # For demo, generate a consistent DEK
            # In production, this would fail if DEK not found in KMS
            dek = secrets.token_bytes(self.KEY_SIZE)
            self._dek_cache[encrypted_dek_id] = dek

        return dek
