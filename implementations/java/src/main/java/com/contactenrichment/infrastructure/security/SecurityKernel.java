package com.contactenrichment.infrastructure.security;

import com.contactenrichment.domain.model.SecurityLabel;

/**
 * Security Kernel - Trusted Computing Base Interface.
 */
public interface SecurityKernel {

    void authorizeContactCreation(SecurityContext context);

    void authorizeRead(SecurityContext context, SecurityLabel dataLabel);

    void authorizeWrite(SecurityContext context, SecurityLabel dataLabel);

    void authorizeEnrichment(SecurityContext context, SecurityLabel contactLabel, SecurityLabel attributeLabel);

    default SecurityContext verifySession(String token) {
        throw new UnsupportedOperationException("verifySession not implemented");
    }

    default void audit(SecurityContext context, String category, String action, String outcome, String details) {
        // no-op default; concrete kernels may forward to AuditService
    }
}
