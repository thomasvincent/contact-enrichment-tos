package com.contactenrichment.infrastructure.persistence;

import com.contactenrichment.infrastructure.security.SecurityContext;
import jakarta.persistence.EntityManager;

/**
 * Utility for applying PostgreSQL Row-Level Security (RLS) session variables
 * consistently across repositories.
 */
public final class RlsSessionUtil {

    private RlsSessionUtil() {}

    /**
     * Apply security context to the current database session using SET LOCAL app.* variables.
     *
     * Note: SET LOCAL does not support parameterized queries in PostgreSQL, so values
     * must be concatenated. All values are validated/sanitized to prevent injection.
     */
    public static void applySecurityContext(EntityManager entityManager, SecurityContext context) {
        // Set clearance levels (ordinal values are integers, safe to concatenate)
        entityManager.createNativeQuery(
            String.format("SET LOCAL app.clearance_conf = '%d'",
                context.getClearance().getConfidentiality().ordinal())
        ).executeUpdate();

        entityManager.createNativeQuery(
            String.format("SET LOCAL app.clearance_integ = '%d'",
                context.getClearance().getIntegrity().ordinal())
        ).executeUpdate();

        // Set principal ID for audit (UUID.toString() is safe - no injection risk)
        entityManager.createNativeQuery(
            String.format("SET LOCAL app.principal_id = '%s'",
                context.getPrincipalId().toString())
        ).executeUpdate();

        // Set compartments (comma-separated, validated alphanumeric strings)
        String compartments = String.join(",",
            (context.getCompartments() != null && !context.getCompartments().isEmpty())
                ? context.getCompartments()
                : context.getClearance().getCompartments()
        );
        // Sanitize compartments to prevent injection (allow only alphanumeric, underscore, comma)
        String sanitized = compartments.replaceAll("[^a-zA-Z0-9_,]", "");
        entityManager.createNativeQuery(
            String.format("SET LOCAL app.compartments = '%s'", sanitized)
        ).executeUpdate();
    }
}
