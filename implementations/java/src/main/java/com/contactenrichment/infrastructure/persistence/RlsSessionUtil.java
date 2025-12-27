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
     */
    public static void applySecurityContext(EntityManager entityManager, SecurityContext context) {
        // Set clearance levels
        entityManager.createNativeQuery(
            "SET LOCAL app.clearance_conf = :conf"
        ).setParameter("conf", context.getClearance().getConfidentiality().ordinal())
         .executeUpdate();

        entityManager.createNativeQuery(
            "SET LOCAL app.clearance_integ = :integ"
        ).setParameter("integ", context.getClearance().getIntegrity().ordinal())
         .executeUpdate();

        // Set principal ID for audit
        entityManager.createNativeQuery(
            "SET LOCAL app.principal_id = :principalId"
        ).setParameter("principalId", context.getPrincipalId().toString())
         .executeUpdate();

        // Set compartments (comma-separated)
        String compartments = String.join(",",
            (context.getCompartments() != null && !context.getCompartments().isEmpty())
                ? context.getCompartments()
                : context.getClearance().getCompartments()
        );
        entityManager.createNativeQuery(
            "SET LOCAL app.compartments = :comps"
        ).setParameter("comps", compartments)
         .executeUpdate();
    }
}
