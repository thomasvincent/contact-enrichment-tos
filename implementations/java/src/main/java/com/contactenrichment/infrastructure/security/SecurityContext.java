package com.contactenrichment.infrastructure.security;

import com.contactenrichment.domain.model.SecurityLabel;
import lombok.Value;

import java.time.Instant;
import java.util.UUID;

/**
 * Immutable security context for a request.
 *
 * <p>Established at API gateway and threaded through all operations.
 *
 * @author Security Team
 * @since 1.0.0
 */
@Value
public class SecurityContext {
    UUID requestId;
    UUID sessionId;
    UUID principalId;
    SecurityLabel clearance;
    String authenticatedVia;
    boolean mfaVerified;
    boolean trustedDevice;
    String sourceIp;
    String userAgent;
    Instant requestedAt;
    String declaredPurpose;

    public SecurityContext withPurpose(String purpose) {
        return new SecurityContext(
            requestId, sessionId, principalId, clearance,
            authenticatedVia, mfaVerified, trustedDevice,
            sourceIp, userAgent, requestedAt, purpose
        );
    }
}
