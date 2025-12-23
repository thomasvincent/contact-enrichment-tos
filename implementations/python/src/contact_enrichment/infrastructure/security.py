"""Security kernel for MAC enforcement."""
import logging
from typing import Protocol

from contact_enrichment.domain.contact import IntegrityLevel, SecurityLabel
from contact_enrichment.infrastructure.repository import SecurityContext

logger = logging.getLogger(__name__)


class SecurityError(Exception):
    """Base exception for security violations."""

    pass


class AccessDeniedError(SecurityError):
    """Exception raised when access is denied."""

    pass


class MfaRequiredError(SecurityError):
    """Exception raised when MFA is required but not verified."""

    pass


class SecurityKernel(Protocol):
    """Security kernel interface for MAC enforcement."""

    def authorize_read(self, context: SecurityContext, data_label: SecurityLabel) -> None:
        """Authorize read access (Bell-LaPadula: no read up)."""
        ...

    def authorize_write(self, context: SecurityContext, data_label: SecurityLabel) -> None:
        """Authorize write access (Biba: no write down + Bell-LaPadula)."""
        ...

    def authorize_contact_creation(self, context: SecurityContext) -> None:
        """Authorize contact creation."""
        ...

    def authorize_enrichment(
        self,
        context: SecurityContext,
        contact_label: SecurityLabel,
        attribute_label: SecurityLabel,
    ) -> None:
        """Authorize enrichment operation."""
        ...


class TrustedSecurityKernel:
    """Trusted Security Kernel implementing Bell-LaPadula and Biba models.

    Implements:
    - Bell-LaPadula model (no read up)
    - Biba model (no write down)
    - Compartmentalization (need-to-know)
    - Audit logging for all decisions
    """

    def authorize_read(self, context: SecurityContext, data_label: SecurityLabel) -> None:
        """Authorize read access with Bell-LaPadula enforcement."""
        request_id = context.request_id

        logger.debug(
            f"Authorization check [{request_id}]: principal={context.principal_id}, "
            f"operation=READ, dataLabel={data_label}"
        )

        # Bell-LaPadula: No read up
        if not context.clearance.dominates(data_label):
            logger.warning(
                f"AUTHORIZATION DENIED [{request_id}]: Clearance insufficient for read - "
                f"principal={context.principal_id}, required={data_label}, "
                f"actual={context.clearance}"
            )
            raise AccessDeniedError(
                "Access denied: Your clearance does not dominate the data classification"
            )

        # Check compartments (need-to-know)
        if not context.clearance.compartments.issuperset(data_label.compartments):
            logger.warning(
                f"AUTHORIZATION DENIED [{request_id}]: Missing compartments - "
                f"principal={context.principal_id}, required={data_label.compartments}, "
                f"actual={context.clearance.compartments}"
            )
            raise AccessDeniedError(
                "Access denied: Missing required compartments (need-to-know)"
            )

        logger.info(
            f"AUTHORIZATION GRANTED [{request_id}]: principal={context.principal_id}, "
            f"operation=READ"
        )

    def authorize_write(self, context: SecurityContext, data_label: SecurityLabel) -> None:
        """Authorize write access with Biba and Bell-LaPadula enforcement."""
        request_id = context.request_id

        logger.debug(
            f"Authorization check [{request_id}]: principal={context.principal_id}, "
            f"operation=WRITE, dataLabel={data_label}"
        )

        # Biba: No write down (integrity)
        if data_label.integrity.value > context.clearance.integrity.value:
            logger.warning(
                f"AUTHORIZATION DENIED [{request_id}]: Integrity level insufficient - "
                f"principal={context.principal_id}, required={data_label.integrity}, "
                f"actual={context.clearance.integrity}"
            )
            raise AccessDeniedError(
                "Access denied: Cannot write to higher integrity level (no write down)"
            )

        # Must also be able to read (Bell-LaPadula)
        self.authorize_read(context, data_label)

        logger.info(
            f"AUTHORIZATION GRANTED [{request_id}]: principal={context.principal_id}, "
            f"operation=WRITE"
        )

    def authorize_contact_creation(self, context: SecurityContext) -> None:
        """Authorize contact creation with integrity and MFA checks."""
        request_id = context.request_id

        logger.debug(
            f"Authorization check [{request_id}]: principal={context.principal_id}, "
            f"operation=CREATE_CONTACT"
        )

        # Require minimum Medium integrity for contact creation
        if context.clearance.integrity.value < IntegrityLevel.MEDIUM.value:
            logger.warning(
                f"AUTHORIZATION DENIED [{request_id}]: Insufficient integrity for "
                f"contact creation - principal={context.principal_id}, "
                f"actual={context.clearance.integrity}"
            )
            raise AccessDeniedError(
                "Access denied: Minimum Medium integrity level required for contact creation"
            )

        # Require MFA for sensitive operations
        if not context.mfa_verified:
            logger.warning(
                f"AUTHORIZATION DENIED [{request_id}]: MFA required - "
                f"principal={context.principal_id}"
            )
            raise MfaRequiredError("Access denied: Multi-factor authentication required")

        # Require declared purpose for GDPR/CCPA compliance
        if not context.declared_purpose:
            logger.warning(
                f"AUTHORIZATION DENIED [{request_id}]: No processing purpose declared - "
                f"principal={context.principal_id}"
            )
            raise AccessDeniedError(
                "Access denied: Processing purpose must be declared (GDPR compliance)"
            )

        logger.info(
            f"AUTHORIZATION GRANTED [{request_id}]: principal={context.principal_id}, "
            f"operation=CREATE_CONTACT"
        )

    def authorize_enrichment(
        self,
        context: SecurityContext,
        contact_label: SecurityLabel,
        attribute_label: SecurityLabel,
    ) -> None:
        """Authorize enrichment with label validation."""
        request_id = context.request_id

        logger.debug(
            f"Authorization check [{request_id}]: principal={context.principal_id}, "
            f"operation=ENRICH, contactLabel={contact_label}, "
            f"attributeLabel={attribute_label}"
        )

        # Must be able to write to contact
        self.authorize_write(context, contact_label)

        # Attribute label must not exceed contact label (prevent upgrade)
        if not contact_label.dominates(attribute_label):
            logger.warning(
                f"AUTHORIZATION DENIED [{request_id}]: Attribute label exceeds contact "
                f"label - principal={context.principal_id}, contactLabel={contact_label}, "
                f"attributeLabel={attribute_label}"
            )
            raise AccessDeniedError(
                "Access denied: Attribute security label exceeds contact label"
            )

        logger.info(
            f"AUTHORIZATION GRANTED [{request_id}]: principal={context.principal_id}, "
            f"operation=ENRICH"
        )
