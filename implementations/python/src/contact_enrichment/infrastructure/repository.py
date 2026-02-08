"""Contact repository implementation using SQLAlchemy with PostgreSQL."""

import logging
from typing import Optional
from uuid import UUID

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from contact_enrichment.domain.contact import Contact, EncryptedValue, SecurityLabel

logger = logging.getLogger(__name__)


class SecurityContext:
    """Security context for authorization."""

    def __init__(
        self,
        request_id: UUID,
        principal_id: UUID,
        clearance: SecurityLabel,
        mfa_verified: bool,
        declared_purpose: Optional[str] = None,
    ):
        self.request_id = request_id
        self.principal_id = principal_id
        self.clearance = clearance
        self.mfa_verified = mfa_verified
        self.declared_purpose = declared_purpose


class ContactRepository:
    """Repository for Contact aggregate with Row-Level Security."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def _apply_security_context(self, context: SecurityContext) -> None:
        """Set PostgreSQL session variables for RLS enforcement."""
        await self.session.execute(
            text("SET LOCAL app.clearance_conf = :conf"),
            {"conf": context.clearance.confidentiality.value},
        )
        await self.session.execute(
            text("SET LOCAL app.clearance_integ = :integ"),
            {"integ": context.clearance.integrity.value},
        )
        await self.session.execute(
            text("SET LOCAL app.principal_id = :principal_id"),
            {"principal_id": str(context.principal_id)},
        )
        logger.debug(
            f"Applied RLS context: principal={context.principal_id}, "
            f"clearance={context.clearance}"
        )

    async def find_by_id(self, contact_id: UUID, context: SecurityContext) -> Optional[Contact]:
        """Find contact by ID with RLS enforcement."""
        await self._apply_security_context(context)

        # Simplified query - in production would use SQLAlchemy ORM models
        result = await self.session.execute(
            text("""
                SELECT id, canonical_email_ciphertext, canonical_email_key_id,
                       canonical_email_algorithm, canonical_email_iv,
                       canonical_email_auth_tag, canonical_email_hash,
                       confidentiality_level, integrity_level, compartments,
                       created_at, created_by, updated_at, version
                FROM contacts
                WHERE id = :contact_id
                """),
            {"contact_id": contact_id},
        )

        row = result.fetchone()
        if not row:
            logger.debug(f"Contact not found or access denied: id={contact_id}")
            return None

        logger.info(f"Contact retrieved: id={contact_id}, principal={context.principal_id}")

        # Reconstruct Contact from row (simplified)
        return self._row_to_contact(row)

    async def find_by_email_hash(
        self, email_hash: bytes, context: SecurityContext
    ) -> Optional[Contact]:
        """Find contact by email hash."""
        await self._apply_security_context(context)

        result = await self.session.execute(
            text("""
                SELECT id, canonical_email_ciphertext, canonical_email_key_id,
                       canonical_email_algorithm, canonical_email_iv,
                       canonical_email_auth_tag, canonical_email_hash,
                       confidentiality_level, integrity_level, compartments,
                       created_at, created_by, updated_at, version
                FROM contacts
                WHERE canonical_email_hash = :email_hash
                """),
            {"email_hash": email_hash},
        )

        row = result.fetchone()
        if not row:
            return None

        logger.info(f"Contact retrieved by email hash, principal={context.principal_id}")
        return self._row_to_contact(row)

    async def save(self, contact: Contact, context: SecurityContext) -> None:
        """Save contact with RLS enforcement."""
        await self._apply_security_context(context)

        if contact.version == 1:
            # Insert new contact
            await self.session.execute(
                text("""
                    INSERT INTO contacts (
                        id, canonical_email_ciphertext, canonical_email_key_id,
                        canonical_email_algorithm, canonical_email_iv,
                        canonical_email_auth_tag, canonical_email_hash,
                        confidentiality_level, integrity_level, compartments,
                        created_at, created_by, updated_at, version
                    ) VALUES (
                        :id, :ciphertext, :key_id, :algorithm, :iv, :auth_tag,
                        :email_hash, :conf, :integ, :compartments,
                        :created_at, :created_by, :updated_at, :version
                    )
                    """),
                {
                    "id": contact.id,
                    "ciphertext": contact.canonical_email.ciphertext,
                    "key_id": contact.canonical_email.key_id,
                    "algorithm": contact.canonical_email.algorithm,
                    "iv": contact.canonical_email.iv,
                    "auth_tag": contact.canonical_email.auth_tag,
                    "email_hash": contact.canonical_email_hash,
                    "conf": contact.security_label.confidentiality.value,
                    "integ": contact.security_label.integrity.value,
                    "compartments": list(contact.security_label.compartments),
                    "created_at": contact.created_at,
                    "created_by": contact.created_by,
                    "updated_at": contact.updated_at,
                    "version": contact.version,
                },
            )
            logger.info(f"Contact created: id={contact.id}, principal={context.principal_id}")
        else:
            # Update existing contact with optimistic locking
            result = await self.session.execute(
                text("""
                    UPDATE contacts
                    SET updated_at = :updated_at, version = version + 1
                    WHERE id = :id AND version = :version
                    """),
                {
                    "id": contact.id,
                    "updated_at": contact.updated_at,
                    "version": contact.version,
                },
            )
            if result.rowcount == 0:
                raise ValueError("Optimistic lock error: contact was modified")

            logger.info(
                f"Contact updated: id={contact.id}, version={contact.version}, "
                f"principal={context.principal_id}"
            )

        await self.session.commit()

    async def delete(self, contact_id: UUID, context: SecurityContext) -> None:
        """Delete contact (GDPR right to erasure)."""
        await self._apply_security_context(context)

        await self.session.execute(
            text("DELETE FROM contacts WHERE id = :id"),
            {"id": contact_id},
        )
        await self.session.commit()

        logger.warning(f"Contact deleted: id={contact_id}, principal={context.principal_id}")

    async def exists_by_email_hash(self, email_hash: bytes, context: SecurityContext) -> bool:
        """Check if contact exists by email hash."""
        await self._apply_security_context(context)

        result = await self.session.execute(
            text("SELECT COUNT(*) FROM contacts WHERE canonical_email_hash = :hash"),
            {"hash": email_hash},
        )
        count = result.scalar()
        return count > 0

    def _row_to_contact(self, row) -> Contact:
        """Convert database row to Contact domain model."""

        encrypted_email = EncryptedValue(
            ciphertext=row.canonical_email_ciphertext,
            key_id=row.canonical_email_key_id,
            algorithm=row.canonical_email_algorithm,
            iv=row.canonical_email_iv,
            auth_tag=row.canonical_email_auth_tag,
        )

        security_label = SecurityLabel(
            confidentiality=row.confidentiality_level,
            integrity=row.integrity_level,
            compartments=frozenset(row.compartments or []),
        )

        # Simplified Contact reconstruction
        contact = Contact(
            id=row.id,
            canonical_email=encrypted_email,
            canonical_email_hash=row.canonical_email_hash,
            full_name=None,
            security_label=security_label,
            enriched_attributes=[],
            created_at=row.created_at,
            created_by=row.created_by,
            updated_at=row.updated_at,
            version=row.version,
        )

        return contact
