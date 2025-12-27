package com.contactenrichment.infrastructure.audit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

@Component
@RequiredArgsConstructor
@Slf4j
public class OutboxPublisher {
    private final OutboxEventRepository repository;

    @Scheduled(fixedDelay = 10000)
    public void publish() {
        // Human note: dev stub — mark any unprocessed events as processed after logging
        repository.findAll().stream()
                .filter(e -> !e.isProcessed())
                .forEach(e -> {
                    if (log.isInfoEnabled()) {
                        log.info("OUTBOX publish category={} action={} resourceId={} principal={} detail={} createdAt={}",
                                e.getCategory(), e.getAction(), e.getResourceId(), e.getPrincipalId(), e.getDetail(), e.getCreatedAt());
                    }
                    e.setProcessed(true);
                    repository.save(e);
                });
    }
}