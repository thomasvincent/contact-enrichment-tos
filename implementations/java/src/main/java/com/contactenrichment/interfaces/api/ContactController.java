package com.contactenrichment.interfaces.api;

import com.contactenrichment.application.*;
import com.contactenrichment.domain.model.*;
import com.contactenrichment.infrastructure.security.SecurityContext;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * REST API for Contact operations.
 *
 * @author Thomas Vincent
 * @since 1.0.0
 */
@RestController
@RequestMapping("/api/v1/contacts")
@Tag(name = "Contacts", description = "Contact management API")
@SecurityRequirement(name = "bearer-jwt")
@RequiredArgsConstructor
@Slf4j
public class ContactController {

    private final ContactService contactService;

    @PostMapping
    @Operation(summary = "Create a new contact")
    public ResponseEntity<ContactCreatedResponse> createContact(
            @Valid @RequestBody CreateContactRequest request,
            @RequestAttribute SecurityContext securityContext) {

        byte[] emailHash = ContactService.hashEmail(request.email);

        UUID contactId = contactService.createContact(
            new CreateContactCommand(
                request.email,
                emailHash,
                request.fullName,
                SecurityLabel.confidentialPii(), // Default for new contacts
                request.consentType,
                request.legalBasis,
                request.purposeCodes,
                request.consentEvidenceRef
            ),
            securityContext
        );

        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(new ContactCreatedResponse(contactId));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get contact by ID")
    public ResponseEntity<ContactResponse> getContact(
            @PathVariable UUID id,
            @RequestAttribute SecurityContext securityContext) {

        ContactDetailsDTO contact = contactService.getContact(id, securityContext);

        return ResponseEntity.ok(new ContactResponse(
            contact.id(),
            contact.email(),
            contact.fullName(),
            contact.securityLabel().getConfidentiality().name(),
            contact.enrichmentCount(),
            contact.createdAt()
        ));
    }

    @PostMapping("/{id}/enrich")
    @Operation(summary = "Add enrichment to contact")
    public ResponseEntity<Void> enrichContact(
            @PathVariable UUID id,
            @Valid @RequestBody EnrichRequest request,
            @RequestAttribute SecurityContext securityContext) {

        contactService.enrichContact(
            new EnrichContactCommand(
                id,
                request.attributeType,
                request.value,
                request.provenanceId,
                request.confidenceScore,
                SecurityLabel.confidentialPii()
            ),
            securityContext
        );

        return ResponseEntity.ok().build();
    }
}

// DTOs
record CreateContactRequest(
    @NotBlank @Email String email,
    String fullName,
    @NotNull ConsentType consentType,
    @NotNull LegalBasis legalBasis,
    @NotNull List<String> purposeCodes,
    String consentEvidenceRef
) {}

record ContactCreatedResponse(UUID id) {}

record ContactResponse(
    UUID id,
    String email,
    String fullName,
    String securityLevel,
    int enrichmentCount,
    java.time.Instant createdAt
) {}

record EnrichRequest(
    @NotNull AttributeType attributeType,
    @NotBlank String value,
    @NotNull UUID provenanceId,
    Double confidenceScore
) {}
