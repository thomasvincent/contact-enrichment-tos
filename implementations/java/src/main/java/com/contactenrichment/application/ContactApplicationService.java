package com.contactenrichment.application;

import com.contactenrichment.domain.model.*;
import com.contactenrichment.domain.repository.ContactRepository;
import com.contactenrichment.infrastructure.crypto.CryptoService;
import com.contactenrichment.infrastructure.security.SecurityContext;
import com.contactenrichment.infrastructure.security.SecurityKernel;
import com.contactenrichment.interfaces.api.dto.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Application service for Contact operations with DTO mapping.
 *
 * Orchestrates use cases and maps between DTOs and domain models.
 * Idiomatic Spring Boot service with @Service annotation.
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class ContactApplicationService {

    private final ContactRepository contactRepository;
    private final CryptoService cryptoService;
    private final SecurityKernel securityKernel;
    private final SecurityContextProvider securityContextProvider;

    /**
     * Create a new contact.
     */
    public ContactResponse createContact(CreateContactRequest request) {
        SecurityContext context = securityContextProvider.getCurrentContext();

        log.info("Creating contact with email: {}", maskEmail(request.getEmail()));

        // Authorize operation
        securityKernel.authorizeContactCreation(context);

        // Encrypt email
        byte[] emailBytes = request.getEmail().getBytes(StandardCharsets.UTF_8);
        EncryptedValue encryptedEmail = cryptoService.encrypt(emailBytes, "email-key");

        // Compute email hash for uniqueness constraint
        byte[] emailHash = cryptoService.hash(emailBytes);

        // Check if contact already exists
        if (contactRepository.existsByEmailHash(emailHash, context)) {
            throw new IllegalArgumentException("Contact already exists with this email");
        }

        // Encrypt full name if provided
        EncryptedValue encryptedFullName = null;
        if (request.getFullName() != null && !request.getFullName().isBlank()) {
            byte[] fullNameBytes = request.getFullName().getBytes(StandardCharsets.UTF_8);
            encryptedFullName = cryptoService.encrypt(fullNameBytes, "name-key");
        }

        // Create security label
        SecurityLabel securityLabel = new SecurityLabel(
            ConfidentialityLevel.valueOf(request.getConfidentialityLevel()),
            IntegrityLevel.valueOf(request.getIntegrityLevel()),
            request.getCompartments(),
            java.util.Set.of() // caveats
        );

        // Create contact aggregate
        Contact contact = Contact.create(
            UUID.randomUUID(),
            encryptedEmail,
            emailHash,
            encryptedFullName,
            securityLabel,
            context.getPrincipalId()
        );

        // Record consent
        contact.recordConsent(
            ConsentType.EXPLICIT_OPT_IN,
            LegalBasis.valueOf(request.getLegalBasis()),
            List.of(request.getProcessingPurpose()),
            "consent-evidence-" + UUID.randomUUID()
        );

        // Persist
        contactRepository.save(contact, context);

        log.info("Contact created successfully: id={}", contact.getId());

        // Map to response
        return mapToResponse(contact, context);
    }

    /**
     * Get contact by ID.
     */
    @Transactional(readOnly = true)
    public ContactResponse getContact(UUID id) {
        SecurityContext context = securityContextProvider.getCurrentContext();

        log.info("Retrieving contact: id={}", id);

        Contact contact = contactRepository.findById(id, context)
            .orElseThrow(() -> new IllegalArgumentException("Contact not found: " + id));

        return mapToResponse(contact, context);
    }

    /**
     * Enrich contact with additional attributes.
     */
    public ContactResponse enrichContact(UUID id, EnrichContactRequest request) {
        SecurityContext context = securityContextProvider.getCurrentContext();

        log.info("Enriching contact: id={}, attributeType={}",
            id, request.getAttributeType());

        // Load contact aggregate
        Contact contact = contactRepository.findById(id, context)
            .orElseThrow(() -> new IllegalArgumentException("Contact not found: " + id));

        // Encrypt attribute value
        byte[] valueBytes = request.getValue().getBytes(StandardCharsets.UTF_8);
        EncryptedValue encryptedValue = cryptoService.encrypt(valueBytes, "attr-key");

        // Create provenance record (simplified - would integrate with Provenance BC)
        UUID provenanceId = UUID.randomUUID();

        // Add enrichment to aggregate
        contact.addEnrichment(
            AttributeType.valueOf(request.getAttributeType()),
            encryptedValue,
            provenanceId,
            request.getConfidenceScore(),
            contact.getSecurityLabel(), // Inherit contact's security label
            context.getPrincipalId()
        );

        // Persist updated aggregate
        contactRepository.save(contact, context);

        log.info("Contact enriched successfully: id={}", id);

        return mapToResponse(contact, context);
    }

    /**
     * Delete contact (GDPR right to erasure).
     */
    public void deleteContact(UUID id) {
        SecurityContext context = securityContextProvider.getCurrentContext();

        log.warn("Deleting contact: id={}", id);

        // Authorize deletion
        Contact contact = contactRepository.findById(id, context)
            .orElseThrow(() -> new IllegalArgumentException("Contact not found: " + id));

        securityKernel.authorizeWrite(context, contact.getSecurityLabel());

        // Delete
        contactRepository.delete(id, context);

        log.warn("Contact deleted successfully: id={}", id);
    }

    /**
     * Search by email hash.
     */
    @Transactional(readOnly = true)
    public ContactResponse searchByEmailHash(String emailHashBase64) {
        SecurityContext context = securityContextProvider.getCurrentContext();

        byte[] emailHash = Base64.getDecoder().decode(emailHashBase64);

        Contact contact = contactRepository.findByEmailHash(emailHash, context)
            .orElseThrow(() -> new IllegalArgumentException("Contact not found"));

        return mapToResponse(contact, context);
    }

    /**
     * Map Contact domain model to DTO response.
     */
    private ContactResponse mapToResponse(Contact contact, SecurityContext context) {
        // Decrypt email (if authorized)
        String email = null;
        try {
            securityKernel.authorizeRead(context, contact.getSecurityLabel());
            byte[] emailBytes = cryptoService.decrypt(contact.getCanonicalEmail());
            email = new String(emailBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            log.debug("Cannot decrypt email for contact {}: access denied", contact.getId());
        }

        // Decrypt full name (if present and authorized)
        String fullName = null;
        if (contact.getFullName() != null) {
            try {
                byte[] fullNameBytes = cryptoService.decrypt(contact.getFullName());
                fullName = new String(fullNameBytes, StandardCharsets.UTF_8);
            } catch (Exception e) {
                log.debug("Cannot decrypt full name for contact {}: access denied", contact.getId());
            }
        }

        // Map security label
        ContactResponse.SecurityLabelDto securityLabelDto = ContactResponse.SecurityLabelDto.builder()
            .confidentialityLevel(contact.getSecurityLabel().getConfidentiality().name())
            .integrityLevel(contact.getSecurityLabel().getIntegrity().name())
            .compartments(contact.getSecurityLabel().getCompartments().stream().toList())
            .build();

        // Map current attributes
        List<ContactResponse.EnrichedAttributeDto> attributeDtos = contact.getCurrentAttributes()
            .stream()
            .map(attr -> {
                String value = null;
                try {
                    byte[] valueBytes = cryptoService.decrypt(attr.getEncryptedValue());
                    value = new String(valueBytes, StandardCharsets.UTF_8);
                } catch (Exception e) {
                    log.debug("Cannot decrypt attribute: access denied");
                }

                return ContactResponse.EnrichedAttributeDto.builder()
                    .id(attr.getId())
                    .attributeType(attr.getAttributeType().name())
                    .value(value)
                    .confidenceScore(attr.getConfidenceScore())
                    .validFrom(attr.getValidFrom())
                    .provenanceId(attr.getProvenanceId())
                    .build();
            })
            .collect(Collectors.toList());

        return ContactResponse.builder()
            .id(contact.getId())
            .email(email)
            .fullName(fullName)
            .securityLabel(securityLabelDto)
            .currentAttributes(attributeDtos)
            .createdAt(contact.getCreatedAt())
            .updatedAt(contact.getUpdatedAt())
            .version(contact.getVersion())
            .build();
    }

    private String maskEmail(String email) {
        if (email == null || email.length() < 3) {
            return "***";
        }
        int atIndex = email.indexOf('@');
        if (atIndex > 0) {
            return email.charAt(0) + "***" + email.substring(atIndex);
        }
        return email.charAt(0) + "***";
    }
}
