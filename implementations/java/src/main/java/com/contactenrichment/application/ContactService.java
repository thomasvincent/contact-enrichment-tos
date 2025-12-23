package com.contactenrichment.application;

import com.contactenrichment.domain.model.*;
import com.contactenrichment.domain.repository.ContactRepository;
import com.contactenrichment.infrastructure.crypto.CryptoService;
import com.contactenrichment.infrastructure.security.SecurityContext;
import com.contactenrichment.infrastructure.security.SecurityKernel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.UUID;

/**
 * Application service for Contact operations.
 *
 * <p>Orchestrates use cases in the Contact Core bounded context.
 *
 * @author Platform Team
 * @since 1.0.0
 */
@Service
@Transactional
@RequiredArgsConstructor
@Slf4j
public class ContactService {

    private final ContactRepository contactRepository;
    private final CryptoService cryptoService;
    private final SecurityKernel securityKernel;

    /**
     * Create a new contact.
     *
     * @param command Create contact command
     * @param context Security context
     * @return Created contact ID
     */
    public UUID createContact(CreateContactCommand command, SecurityContext context) {
        log.info("Creating contact for email hash: {}",
            bytesToHex(command.emailHash()));

        // Validate authorization
        securityKernel.authorizeContactCreation(context);

        // Check for duplicates
        contactRepository.findByEmailHash(command.emailHash(), context)
            .ifPresent(existing -> {
                throw new IllegalStateException("Contact already exists");
            });

        // Encrypt PII
        EncryptedValue encryptedEmail = cryptoService.encrypt(
            command.email().getBytes(StandardCharsets.UTF_8),
            context
        );

        EncryptedValue encryptedName = command.fullName() != null
            ? cryptoService.encrypt(
                command.fullName().getBytes(StandardCharsets.UTF_8),
                context
            )
            : null;

        // Create aggregate
        Contact contact = Contact.create(
            UUID.randomUUID(),
            encryptedEmail,
            command.emailHash(),
            encryptedName,
            command.securityLabel(),
            context.getPrincipalId()
        );

        // Record initial consent
        contact.recordConsent(
            command.consentType(),
            command.legalBasis(),
            command.purposeCodes(),
            command.consentEvidenceRef()
        );

        // Persist
        contactRepository.save(contact, context);

        log.info("Contact created: {}", contact.getId());
        return contact.getId();
    }

    /**
     * Add enrichment to existing contact.
     *
     * @param command Enrichment command
     * @param context Security context
     */
    public void enrichContact(EnrichContactCommand command, SecurityContext context) {
        log.info("Enriching contact: {}", command.contactId());

        // Retrieve contact
        Contact contact = contactRepository.findById(command.contactId(), context)
            .orElseThrow(() -> new IllegalArgumentException("Contact not found"));

        // Encrypt enrichment value
        EncryptedValue encryptedValue = cryptoService.encrypt(
            command.value().getBytes(StandardCharsets.UTF_8),
            context
        );

        // Add enrichment
        contact.addEnrichment(
            command.attributeType(),
            encryptedValue,
            command.provenanceId(),
            command.confidenceScore(),
            command.attributeLabel(),
            context.getPrincipalId()
        );

        // Persist
        contactRepository.save(contact, context);

        log.info("Contact enriched: {} with {}",
            command.contactId(), command.attributeType());
    }

    /**
     * Get contact details.
     *
     * @param contactId Contact ID
     * @param context Security context
     * @return Contact details DTO
     */
    @Transactional(readOnly = true)
    public ContactDetailsDTO getContact(UUID contactId, SecurityContext context) {
        Contact contact = contactRepository.findById(contactId, context)
            .orElseThrow(() -> new IllegalArgumentException("Contact not found"));

        // Decrypt for presentation
        String email = cryptoService.decrypt(contact.getCanonicalEmail(), context);
        String name = contact.getFullName() != null
            ? cryptoService.decrypt(contact.getFullName(), context)
            : null;

        return new ContactDetailsDTO(
            contact.getId(),
            email,
            name,
            contact.getSecurityLabel(),
            contact.getCurrentAttributes().size(),
            contact.getCreatedAt()
        );
    }

    /**
     * Compute SHA-256 hash of email.
     */
    public static byte[] hashEmail(String email) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(email.toLowerCase().trim().getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder hexString = new StringBuilder(2 * bytes.length);
        for (byte b : bytes) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }
        return hexString.toString();
    }
}

record CreateContactCommand(
    String email,
    byte[] emailHash,
    String fullName,
    SecurityLabel securityLabel,
    ConsentType consentType,
    LegalBasis legalBasis,
    List<String> purposeCodes,
    String consentEvidenceRef
) {}

record EnrichContactCommand(
    UUID contactId,
    AttributeType attributeType,
    String value,
    UUID provenanceId,
    Double confidenceScore,
    SecurityLabel attributeLabel
) {}

record ContactDetailsDTO(
    UUID id,
    String email,
    String fullName,
    SecurityLabel securityLabel,
    int enrichmentCount,
    java.time.Instant createdAt
) {}

record ContactSearchCriteria(
    String fullTextQuery,
    String companyFilter,
    Boolean enrichedOnly,
    int page,
    int size
) {}
