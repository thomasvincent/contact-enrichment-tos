package com.contactenrichment.infrastructure.audit;

import java.time.Instant;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@lombok.RequiredArgsConstructor
public class DefaultAuditService implements AuditService {
    private final OutboxEventRepository outbox;

    @Override
    public void record(String category, String action, String resourceId, String principalId, String detail) {
        log.info("AUDIT category={} action={} resourceId={} principal={} detail={}",
                category, action, resourceId, principalId, detail);
        try {
            OutboxEvent evt = OutboxEvent.builder()
                    .category(category)
                    .action(action)
                    .resourceId(resourceId)
                    .principalId(principalId)
                    .detail(detail)
                    .createdAt(Instant.now())
                    .processed(false)
                    .build();
            outbox.save(evt);
        } catch (Exception ignored) {
            // Human note: audit persistence is best-effort; never fail the main flow
        }
    }
}
