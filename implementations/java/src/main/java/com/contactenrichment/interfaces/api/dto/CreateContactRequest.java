package com.contactenrichment.interfaces.api.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;

/**
 * Request DTO for creating a new contact.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CreateContactRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be valid")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    private String email;

    @Size(max = 255, message = "Full name must not exceed 255 characters")
    private String fullName;

    @NotNull(message = "Confidentiality level is required")
    private String confidentialityLevel;

    @NotNull(message = "Integrity level is required")
    private String integrityLevel;

    @NotNull(message = "Compartments are required")
    private Set<String> compartments;

    @NotNull(message = "Processing purpose is required")
    @Size(max = 500, message = "Processing purpose must not exceed 500 characters")
    private String processingPurpose;

    @NotNull(message = "Legal basis is required")
    private String legalBasis;

    @NotNull(message = "Consent is required")
    private Boolean consentGranted;
}
