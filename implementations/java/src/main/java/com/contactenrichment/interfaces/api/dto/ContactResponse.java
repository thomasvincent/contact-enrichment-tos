package com.contactenrichment.interfaces.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Response DTO for contact information.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ContactResponse {

    private UUID id;
    private String email; // Decrypted for authorized users
    private String fullName; // Decrypted for authorized users
    private SecurityLabelDto securityLabel;
    private List<EnrichedAttributeDto> currentAttributes;
    private Instant createdAt;
    private Instant updatedAt;
    private Long version;

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class SecurityLabelDto {
        private String confidentialityLevel;
        private String integrityLevel;
        private List<String> compartments;
    }

    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class EnrichedAttributeDto {
        private UUID id;
        private String attributeType;
        private String value; // Decrypted
        private Double confidenceScore;
        private Instant validFrom;
        private UUID provenanceId;
    }
}
