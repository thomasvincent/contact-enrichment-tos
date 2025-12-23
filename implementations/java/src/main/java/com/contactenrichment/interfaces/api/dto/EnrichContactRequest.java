package com.contactenrichment.interfaces.api.dto;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Request DTO for enriching a contact with new attributes.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EnrichContactRequest {

    @NotNull(message = "Attribute type is required")
    private String attributeType;

    @NotBlank(message = "Value is required")
    @Size(max = 1000, message = "Value must not exceed 1000 characters")
    private String value;

    @NotNull(message = "Confidence score is required")
    @DecimalMin(value = "0.0", message = "Confidence score must be at least 0.0")
    @DecimalMax(value = "1.0", message = "Confidence score must be at most 1.0")
    private Double confidenceScore;

    @NotBlank(message = "Provenance source is required")
    @Size(max = 255, message = "Provenance source must not exceed 255 characters")
    private String provenanceSource;

    @Size(max = 1000, message = "Provenance details must not exceed 1000 characters")
    private String provenanceDetails;
}
