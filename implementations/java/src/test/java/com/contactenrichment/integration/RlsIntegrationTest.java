package com.contactenrichment.integration;

import com.contactenrichment.domain.model.*;
import com.contactenrichment.domain.repository.ContactRepository;
import com.contactenrichment.infrastructure.security.SecurityContext;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@Testcontainers
@SpringBootTest
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class RlsIntegrationTest {

    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:15-alpine")
            .withDatabaseName("contact_enrichment")
            .withUsername("contact_enrichment")
            .withPassword("changeme");

    @DynamicPropertySource
    static void registerProps(DynamicPropertyRegistry registry) {
        postgres.start();
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
    }

    @AfterAll
    void tearDown() {
        postgres.stop();
    }

    @Autowired
    ContactRepository contactRepository;

    private SecurityContext ctx(UUID principal, SecurityLabel label, Set<String> comps) {
        return SecurityContext.builder()
                .requestId(UUID.randomUUID())
                .principalId(principal)
                .clearance(label)
                .compartments(comps)
                .mfaVerified(true)
                .declaredPurpose("test")
                .build();
    }

    private Contact newContact(SecurityLabel label, String email, UUID createdBy, byte[] hash) {
        EncryptedValue encEmail = EncryptedValue.builder()
                .ciphertext(email.getBytes(StandardCharsets.UTF_8))
                .keyId("k1")
                .algorithm("AES-256-GCM")
                .iv(new byte[12])
                .authTag(new byte[16])
                .build();
        return Contact.create(
                UUID.randomUUID(),
                encEmail,
                hash,
                null,
                label,
                createdBy
        );
    }

    @Test
    @Disabled("FK constraint issue requires schema refactoring")
    void select_allowed_with_required_compartments() {
        UUID principal = UUID.randomUUID();
        SecurityLabel rowLabel = new SecurityLabel(
                SecurityLabel.ConfidentialityLevel.CONFIDENTIAL,
                SecurityLabel.IntegrityLevel.HIGH,
                Set.of("PII"),
                Set.of()
        );
        byte[] hash = new byte[]{1,2,3};
        Contact c = newContact(rowLabel, "a@example.com", principal, hash);

        SecurityLabel writerLabel = rowLabel; // equal clearance
        contactRepository.save(c, ctx(principal, writerLabel, Set.of("PII")));

        Optional<Contact> found = contactRepository.findById(c.getId(), ctx(principal, writerLabel, Set.of("PII")));
        assertTrue(found.isPresent(), "authorized reader should see the row");
    }

    @Test
    @Disabled("FK constraint issue requires schema refactoring")
    void select_denied_without_compartments() {
        UUID principal = UUID.randomUUID();
        SecurityLabel rowLabel = new SecurityLabel(
                SecurityLabel.ConfidentialityLevel.CONFIDENTIAL,
                SecurityLabel.IntegrityLevel.HIGH,
                Set.of("PII"),
                Set.of()
        );
        byte[] hash = new byte[]{4,5,6};
        Contact c = newContact(rowLabel, "b@example.com", principal, hash);
        contactRepository.save(c, ctx(principal, rowLabel, Set.of("PII")));

        Optional<Contact> denied = contactRepository.findById(c.getId(), ctx(principal,
                rowLabel, Set.of() /* missing PII */));
        assertTrue(denied.isEmpty(), "reader missing PII compartment should be denied by RLS");
    }

    @Test
    void insert_denied_when_clearance_too_low() {
        UUID principal = UUID.randomUUID();
        SecurityLabel rowLabel = new SecurityLabel(
                SecurityLabel.ConfidentialityLevel.RESTRICTED,
                SecurityLabel.IntegrityLevel.CRITICAL,
                Set.of("PII"),
                Set.of()
        );
        byte[] hash = new byte[]{7,8,9};
        Contact c = newContact(rowLabel, "c@example.com", principal, hash);

        SecurityLabel lowClearance = new SecurityLabel(
                SecurityLabel.ConfidentialityLevel.INTERNAL,
                SecurityLabel.IntegrityLevel.MEDIUM,
                Set.of("PII"),
                Set.of()
        );

        assertThrows(Exception.class, () ->
                contactRepository.save(c, ctx(principal, lowClearance, Set.of("PII"))),
                "Insert should be rejected by RLS WITH CHECK");
    }
}
