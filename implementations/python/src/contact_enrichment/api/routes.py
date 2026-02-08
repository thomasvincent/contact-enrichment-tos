"""FastAPI routes for contact operations."""

import logging
from typing import List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr, Field, validator

from contact_enrichment.domain.contact import (
    ConfidentialityLevel,
    IntegrityLevel,
    SecurityLabel,
)
from contact_enrichment.infrastructure.crypto import CryptoService
from contact_enrichment.infrastructure.repository import ContactRepository, SecurityContext
from contact_enrichment.infrastructure.security import (
    AccessDeniedError,
    MfaRequiredError,
    SecurityKernel,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/contacts", tags=["contacts"])


# Request/Response Models with Pydantic validation
class CreateContactRequest(BaseModel):
    """Request model for creating a contact."""

    email: EmailStr = Field(..., description="Contact email address")
    full_name: Optional[str] = Field(None, max_length=255, description="Full name")
    confidentiality_level: str = Field(..., description="Confidentiality level")
    integrity_level: str = Field(..., description="Integrity level")
    compartments: List[str] = Field(default_factory=list, description="Security compartments")
    processing_purpose: str = Field(..., max_length=500, description="Processing purpose")
    consent_granted: bool = Field(..., description="Consent granted")

    @validator("confidentiality_level")
    def validate_confidentiality(cls, v):
        valid_levels = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Must be one of: {valid_levels}")
        return v.upper()

    @validator("integrity_level")
    def validate_integrity(cls, v):
        valid_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        if v.upper() not in valid_levels:
            raise ValueError(f"Must be one of: {valid_levels}")
        return v.upper()

    class Config:
        schema_extra = {
            "example": {
                "email": "user@example.com",
                "full_name": "John Doe",
                "confidentiality_level": "CONFIDENTIAL",
                "integrity_level": "HIGH",
                "compartments": ["PII"],
                "processing_purpose": "contact_enrichment",
                "consent_granted": True,
            }
        }


class SecurityLabelResponse(BaseModel):
    """Security label response."""

    confidentiality_level: str
    integrity_level: str
    compartments: List[str]


class ContactResponse(BaseModel):
    """Response model for contact."""

    id: UUID
    email: Optional[str] = Field(None, description="Decrypted email (if authorized)")
    full_name: Optional[str] = Field(None, description="Decrypted full name (if authorized)")
    security_label: SecurityLabelResponse
    created_at: str
    version: int

    class Config:
        schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "email": "user@example.com",
                "full_name": "John Doe",
                "security_label": {
                    "confidentiality_level": "CONFIDENTIAL",
                    "integrity_level": "HIGH",
                    "compartments": ["PII"],
                },
                "created_at": "2024-01-01T00:00:00Z",
                "version": 1,
            }
        }


class EnrichContactRequest(BaseModel):
    """Request model for enriching a contact."""

    attribute_type: str = Field(..., description="Attribute type")
    value: str = Field(..., max_length=1000, description="Attribute value")
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    provenance_source: str = Field(..., max_length=255, description="Data source")


class ErrorResponse(BaseModel):
    """Standard error response."""

    detail: str
    request_id: Optional[UUID] = None


# Dependency injection
async def get_repository() -> ContactRepository:
    """Get contact repository."""
    # In production: get from dependency injection container
    raise NotImplementedError("Repository dependency not configured")


async def get_crypto_service() -> CryptoService:
    """Get crypto service."""
    # In production: get from dependency injection container
    raise NotImplementedError("Crypto service dependency not configured")


async def get_security_kernel() -> SecurityKernel:
    """Get security kernel."""
    # In production: get from dependency injection container
    raise NotImplementedError("Security kernel dependency not configured")


async def get_security_context() -> SecurityContext:
    """Get current security context from JWT."""
    # In production: extract from JWT token in Authorization header
    raise NotImplementedError("Security context extraction not configured")


# API Endpoints
@router.post(
    "",
    response_model=ContactResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create new contact",
    description="Creates a new contact with encrypted PII and consent tracking",
)
async def create_contact(
    request: CreateContactRequest,
    repository: ContactRepository = Depends(get_repository),
    crypto_service: CryptoService = Depends(get_crypto_service),
    security_kernel: SecurityKernel = Depends(get_security_kernel),
    context: SecurityContext = Depends(get_security_context),
) -> ContactResponse:
    """Create a new contact."""
    from uuid import uuid4

    from contact_enrichment.domain.contact import Contact

    logger.info(f"Creating contact with email: {_mask_email(request.email)}")

    try:
        # Authorize operation
        security_kernel.authorize_contact_creation(context)

        # Encrypt email
        email_bytes = request.email.encode("utf-8")
        encrypted_email = crypto_service.encrypt(email_bytes, "email-key")

        # Compute email hash
        email_hash = crypto_service.hash(email_bytes)

        # Check if contact already exists
        if await repository.exists_by_email_hash(email_hash, context):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Contact already exists with this email",
            )

        # Encrypt full name if provided
        encrypted_full_name = None
        if request.full_name:
            full_name_bytes = request.full_name.encode("utf-8")
            encrypted_full_name = crypto_service.encrypt(full_name_bytes, "name-key")

        # Create security label
        security_label = SecurityLabel(
            confidentiality=ConfidentialityLevel[request.confidentiality_level],
            integrity=IntegrityLevel[request.integrity_level],
            compartments=frozenset(request.compartments),
        )

        # Create contact aggregate
        contact = Contact(
            id=uuid4(),
            canonical_email=encrypted_email,
            canonical_email_hash=email_hash,
            full_name=encrypted_full_name,
            security_label=security_label,
            enriched_attributes=[],
            created_at=None,  # Will be set by Contact
            created_by=context.principal_id,
            updated_at=None,
            version=1,
        )

        # Persist
        await repository.save(contact, context)

        logger.info(f"Contact created successfully: id={contact.id}")

        # Map to response
        return ContactResponse(
            id=contact.id,
            email=None,  # Don't decrypt in creation response
            full_name=None,
            security_label=SecurityLabelResponse(
                confidentiality_level=security_label.confidentiality.name,
                integrity_level=security_label.integrity.name,
                compartments=list(security_label.compartments),
            ),
            created_at=contact.created_at.isoformat() if contact.created_at else "",
            version=contact.version,
        )

    except AccessDeniedError as e:
        logger.warning(f"Authorization failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except MfaRequiredError as e:
        logger.warning(f"MFA required: {e}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Failed to create contact: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.get(
    "/{contact_id}",
    response_model=ContactResponse,
    summary="Get contact by ID",
    description="Retrieves contact details with MAC enforcement",
)
async def get_contact(
    contact_id: UUID,
    repository: ContactRepository = Depends(get_repository),
    crypto_service: CryptoService = Depends(get_crypto_service),
    security_kernel: SecurityKernel = Depends(get_security_kernel),
    context: SecurityContext = Depends(get_security_context),
) -> ContactResponse:
    """Get contact by ID."""
    logger.info(f"Retrieving contact: id={contact_id}")

    try:
        # Load contact
        contact = await repository.find_by_id(contact_id, context)
        if not contact:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contact not found or access denied",
            )

        # Authorize read access
        security_kernel.authorize_read(context, contact.security_label)

        # Decrypt email
        email = None
        try:
            email_bytes = crypto_service.decrypt(contact.canonical_email)
            email = email_bytes.decode("utf-8")
        except Exception as e:
            logger.warning(f"Failed to decrypt email: {e}")

        # Decrypt full name
        full_name = None
        if contact.full_name:
            try:
                full_name_bytes = crypto_service.decrypt(contact.full_name)
                full_name = full_name_bytes.decode("utf-8")
            except Exception as e:
                logger.warning(f"Failed to decrypt full name: {e}")

        return ContactResponse(
            id=contact.id,
            email=email,
            full_name=full_name,
            security_label=SecurityLabelResponse(
                confidentiality_level=contact.security_label.confidentiality.name,
                integrity_level=contact.security_label.integrity.name,
                compartments=list(contact.security_label.compartments),
            ),
            created_at=contact.created_at.isoformat() if contact.created_at else "",
            version=contact.version,
        )

    except AccessDeniedError as e:
        logger.warning(f"Authorization failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Failed to retrieve contact: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


@router.delete(
    "/{contact_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete contact",
    description="Deletes contact and all associated data (GDPR right to erasure)",
)
async def delete_contact(
    contact_id: UUID,
    repository: ContactRepository = Depends(get_repository),
    security_kernel: SecurityKernel = Depends(get_security_kernel),
    context: SecurityContext = Depends(get_security_context),
):
    """Delete contact (GDPR right to erasure)."""
    logger.warning(f"Deleting contact: id={contact_id}")

    try:
        # Load contact to check authorization
        contact = await repository.find_by_id(contact_id, context)
        if not contact:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contact not found",
            )

        # Authorize write access (required for deletion)
        security_kernel.authorize_write(context, contact.security_label)

        # Delete
        await repository.delete(contact_id, context)

        logger.warning(f"Contact deleted successfully: id={contact_id}")

    except AccessDeniedError as e:
        logger.warning(f"Authorization failed: {e}")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except Exception as e:
        logger.error(f"Failed to delete contact: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


def _mask_email(email: str) -> str:
    """Mask email for logging (security)."""
    if len(email) < 3:
        return "***"
    at_index = email.find("@")
    if at_index > 0:
        return f"{email[0]}***{email[at_index:]}"
    return f"{email[0]}***"
