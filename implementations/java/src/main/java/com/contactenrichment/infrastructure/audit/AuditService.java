package com.contactenrichment.infrastructure.audit;

/**
 * Minimal audit service for recording security-relevant events.
 * Human note: initial implementation logs; swap for DB/Kafka outbox in production.
 */
public interface AuditService {
    void record(String category, String action, String resourceId, String principalId, String detail);
}