package com.contactenrichment.infrastructure.security;

/**
 * Security Kernel - Trusted Computing Base Interface.
 *
 * <p>Central enforcement point for all security decisions.
 *
 * @author Security Team
 * @since 1.0.0
 */
public interface SecurityKernel {

    /**
     * Authorize contact creation.
     *
     * @param context Security context
     * @throws SecurityException if not authorized
     */
    void authorizeContactCreation(SecurityContext context);

    /**
     * Authorize contact access.
     *
     * @param context Security context
     * @param resourceLabel Security label of resource
     * @throws SecurityException if not authorized
     */
    void authorizeContactAccess(SecurityContext context, com.contactenrichment.domain.model.SecurityLabel resourceLabel);

    /**
     * Verify session token.
     *
     * @param token JWT or session token
     * @return Security context if valid
     */
    SecurityContext verifySession(String token);

    /**
     * Create audit event.
     *
     * @param context Security context
     * @param category Event category
     * @param action Event action
     * @param outcome Event outcome
     * @param details Details
     */
    void audit(SecurityContext context, String category, String action, String outcome, String details);
}
