package com.contactenrichment.interfaces.api;

import com.contactenrichment.application.ContactApplicationService;
import com.contactenrichment.interfaces.api.dto.*;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

/**
 * REST controller for contact operations.
 *
 * Provides endpoints for:
 * - Creating contacts with encryption and consent tracking
 * - Retrieving contacts with MAC enforcement
 * - Enriching contacts with provenance tracking
 * - Deleting contacts (GDPR right to erasure)
 *
 * Security:
 * - All endpoints require authentication (JWT)
 * - MAC enforced via SecurityKernel
 * - Audit trail for all operations
 * - Rate limiting applied
 *
 * @author Security Team
 * @since 1.0.0
 */
@RestController
@RequestMapping("/api/v1/contacts")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Contacts", description = "Contact management operations")
@SecurityRequirement(name = "bearerAuth")
public class ContactRestController {

    private final ContactApplicationService contactService;

    /**
     * Create a new contact.
     *
     * @param request Contact creation request with consent
     * @return Created contact response with ID
     */
    @PostMapping(
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @ResponseStatus(HttpStatus.CREATED)
    @Operation(
        summary = "Create new contact",
        description = "Creates a new contact with encrypted PII and consent tracking"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "201",
            description = "Contact created successfully",
            content = @Content(schema = @Schema(implementation = ContactResponse.class))
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid request parameters",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Access denied - insufficient clearance",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))
        ),
        @ApiResponse(
            responseCode = "409",
            description = "Contact already exists with this email",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))
        )
    })
    public ResponseEntity<ContactResponse> createContact(
            @Valid @RequestBody CreateContactRequest request) {

        if (log.isInfoEnabled()) {
            log.info("Creating contact with email: {}", maskEmail(request.getEmail()));
        }

        ContactResponse response = contactService.createContact(request);

        if (log.isInfoEnabled()) {
            log.info("Contact created successfully: id={}", response.getId());
        }

        return ResponseEntity
            .status(HttpStatus.CREATED)
            .body(response);
    }

    /**
     * Get contact by ID.
     *
     * @param id Contact ID
     * @return Contact details (decrypted if authorized)
     */
    @GetMapping(
        value = "/{id}",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
        summary = "Get contact by ID",
        description = "Retrieves contact details with MAC enforcement"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Contact retrieved successfully",
            content = @Content(schema = @Schema(implementation = ContactResponse.class))
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Access denied - insufficient clearance",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))
        ),
        @ApiResponse(
            responseCode = "404",
            description = "Contact not found",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))
        )
    })
    public ResponseEntity<ContactResponse> getContact(@PathVariable UUID id) {

        if (log.isInfoEnabled()) {
            log.info("Retrieving contact: id={}", id);
        }

        ContactResponse response = contactService.getContact(id);

        return ResponseEntity.ok(response);
    }

    /**
     * Enrich contact with additional attributes.
     *
     * @param id Contact ID
     * @param request Enrichment request
     * @return Updated contact
     */
    @PostMapping(
        value = "/{id}/enrich",
        consumes = MediaType.APPLICATION_JSON_VALUE,
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
        summary = "Enrich contact",
        description = "Adds enriched attributes to contact with provenance tracking"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Contact enriched successfully",
            content = @Content(schema = @Schema(implementation = ContactResponse.class))
        ),
        @ApiResponse(
            responseCode = "400",
            description = "Invalid enrichment request",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Access denied - insufficient clearance for enrichment",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))
        ),
        @ApiResponse(
            responseCode = "404",
            description = "Contact not found",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))
        )
    })
    public ResponseEntity<ContactResponse> enrichContact(
            @PathVariable UUID id,
            @Valid @RequestBody EnrichContactRequest request) {

        if (log.isInfoEnabled()) {
            log.info("Enriching contact: id={}, attributeType={}",
                id, request.getAttributeType());
        }

        ContactResponse response = contactService.enrichContact(id, request);

        if (log.isInfoEnabled()) {
            log.info("Contact enriched successfully: id={}", id);
        }

        return ResponseEntity.ok(response);
    }

    /**
     * Delete contact (GDPR right to erasure).
     *
     * @param id Contact ID
     * @return No content
     */
    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    @Operation(
        summary = "Delete contact",
        description = "Deletes contact and all associated data (GDPR right to erasure)"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "204",
            description = "Contact deleted successfully"
        ),
        @ApiResponse(
            responseCode = "403",
            description = "Access denied - insufficient clearance for deletion",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))
        ),
        @ApiResponse(
            responseCode = "404",
            description = "Contact not found",
            content = @Content(schema = @Schema(implementation = ErrorResponse.class))
        )
    })
    public ResponseEntity<Void> deleteContact(@PathVariable UUID id) {

        if (log.isWarnEnabled()) {
            log.warn("Deleting contact: id={}", id);
        }

        contactService.deleteContact(id);

        if (log.isWarnEnabled()) {
            log.warn("Contact deleted successfully: id={}", id);
        }

        return ResponseEntity.noContent().build();
    }

    /**
     * Search contacts by email hash.
     *
     * @param emailHash Base64-encoded SHA-256 hash of email
     * @return Contact if found
     */
    @GetMapping(
        value = "/search",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    @Operation(
        summary = "Search contacts by email hash",
        description = "Searches for contact using email hash (privacy-preserving)"
    )
    @ApiResponses({
        @ApiResponse(
            responseCode = "200",
            description = "Contact found",
            content = @Content(schema = @Schema(implementation = ContactResponse.class))
        ),
        @ApiResponse(
            responseCode = "404",
            description = "Contact not found"
        )
    })
    public ResponseEntity<ContactResponse> searchByEmailHash(
            @RequestParam("emailHash") String emailHash) {

        if (log.isInfoEnabled()) {
            log.info("Searching contact by email hash");
        }

        ContactResponse response = contactService.searchByEmailHash(emailHash);

        return ResponseEntity.ok(response);
    }

    /**
     * Mask email for logging (security).
     */
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
