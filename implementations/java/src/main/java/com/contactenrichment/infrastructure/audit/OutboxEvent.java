package com.contactenrichment.infrastructure.audit;

import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Table(name = "outbox_events")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OutboxEvent {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String category;

    @Column(nullable = false)
    private String action;

    @Column(nullable = false, name = "resource_id")
    private String resourceId;

    @Column(nullable = false, name = "principal_id")
    private String principalId;

    @Column(nullable = false)
    private String detail;

    @Column(nullable = false, name = "created_at")
    private Instant createdAt;

    @Column(nullable = false)
    private boolean processed;
}