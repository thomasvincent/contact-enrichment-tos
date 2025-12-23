package com.contactenrichment.application;

import com.contactenrichment.domain.model.ConfidentialityLevel;
import com.contactenrichment.domain.model.IntegrityLevel;
import com.contactenrichment.domain.model.SecurityLabel;
import com.contactenrichment.infrastructure.security.SecurityContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import java.util.Set;
import java.util.UUID;

/**
 * Provider for current security context from Spring Security.
 *
 * Extracts security context from Spring Security's SecurityContextHolder
 * and converts to our domain SecurityContext.
 */
@Component
public class SecurityContextProvider {

    /**
     * Get current security context from Spring Security.
     *
     * In production, this would extract from JWT claims:
     * - Principal ID from subject claim
     * - Clearance from custom claims
     * - MFA status from amr claim
     * - Processing purpose from custom claim
     */
    public SecurityContext getCurrentContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()) {
            throw new SecurityException("No authenticated user");
        }

        // TODO: Extract from JWT claims in production
        // For now, return mock high-privilege context
        return SecurityContext.builder()
            .requestId(UUID.randomUUID())
            .principalId(extractPrincipalId(authentication))
            .clearance(extractClearance(authentication))
            .mfaVerified(extractMfaStatus(authentication))
            .declaredPurpose(extractPurpose(authentication))
            .build();
    }

    private UUID extractPrincipalId(Authentication auth) {
        // TODO: Extract from JWT subject claim
        return UUID.randomUUID();
    }

    private SecurityLabel extractClearance(Authentication auth) {
        // TODO: Extract from JWT custom claims
        return new SecurityLabel(
            ConfidentialityLevel.CONFIDENTIAL,
            IntegrityLevel.HIGH,
            Set.of("PII"),
            Set.of()
        );
    }

    private boolean extractMfaStatus(Authentication auth) {
        // TODO: Extract from JWT amr (authentication methods reference) claim
        return true;
    }

    private String extractPurpose(Authentication auth) {
        // TODO: Extract from JWT custom claim
        return "contact_enrichment";
    }
}
