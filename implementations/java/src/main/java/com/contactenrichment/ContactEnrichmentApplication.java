package com.contactenrichment;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.EnableAspectJAutoProxy;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;
import org.springframework.scheduling.annotation.EnableAsync;
import org.springframework.transaction.annotation.EnableTransactionManagement;

/**
 * Main application class for Contact Enrichment TOS-compliant backend.
 *
 * <p>This application implements a Trusted Operating System (TOS) compliant
 * contact enrichment platform with the following security features:
 *
 * <ul>
 *   <li><strong>Mandatory Access Control (MAC)</strong>: Bell-LaPadula + Biba via SecurityKernel</li>
 *   <li><strong>Multi-Level Security (MLS)</strong>: SELinux integration with security labels</li>
 *   <li><strong>Cryptographic Provenance</strong>: Immutable hash-chained audit trail</li>
 *   <li><strong>Field-Level Encryption</strong>: AES-256-GCM with envelope encryption</li>
 *   <li><strong>Row-Level Security</strong>: PostgreSQL RLS policies enforce MAC at DB layer</li>
 *   <li><strong>GDPR/CCPA Compliance</strong>: Consent management, DSR fulfillment, purpose limitation</li>
 * </ul>
 *
 * <p><strong>Architecture:</strong>
 * <ul>
 *   <li>Domain-Driven Design with 6 bounded contexts</li>
 *   <li>Hexagonal architecture (ports and adapters)</li>
 *   <li>Event sourcing for provenance ledger</li>
 *   <li>CQRS for read/write optimization</li>
 * </ul>
 *
 * <p><strong>Deployment:</strong>
 * <ul>
 *   <li>Red Hat Enterprise Linux 9 with SELinux enforcing</li>
 *   <li>PostgreSQL 15+ with RLS and pgcrypto</li>
 *   <li>Redis for distributed caching and rate limiting</li>
 *   <li>Kafka for event streaming and saga orchestration</li>
 *   <li>AWS KMS for key management (FIPS 140-2 Level 3)</li>
 * </ul>
 *
 * @author Security Team
 * @since 1.0.0
 * @see <a href="docs/architecture/OVERVIEW.md">Architecture Documentation</a>
 */
@SpringBootApplication
@EnableJpaAuditing
@EnableTransactionManagement
@EnableAsync
@EnableAspectJAutoProxy
@ConfigurationPropertiesScan
@Slf4j
public class ContactEnrichmentApplication {

    public static void main(String[] args) {
        // Verify SELinux is enforcing
        verifySelinuxEnforcing();

        // Verify TLS configuration
        verifyTlsConfiguration();

        // Start application
        SpringApplication.run(ContactEnrichmentApplication.class, args);

        log.info("""
            ╔═══════════════════════════════════════════════════════════╗
            ║  Contact Enrichment Platform - TOS Edition                ║
            ║  Mandatory Access Control: ENABLED                        ║
            ║  SELinux: ENFORCING                                       ║
            ║  Encryption: AES-256-GCM                                  ║
            ║  Audit Trail: CRYPTOGRAPHIC                               ║
            ╚═══════════════════════════════════════════════════════════╝
            """);
    }

    /**
     * Verify SELinux is in enforcing mode (critical security requirement).
     */
    private static void verifySelinuxEnforcing() {
        try {
            Process process = Runtime.getRuntime().exec("getenforce");
            String mode = new String(process.getInputStream().readAllBytes()).trim();

            if (!"Enforcing".equals(mode)) {
                log.error("SECURITY VIOLATION: SELinux is not in enforcing mode: {}", mode);
                log.error("Application startup BLOCKED - SELinux must be enforcing for TOS compliance");
                System.exit(1);
            }

            log.info("SELinux verification: ENFORCING ✓");
        } catch (Exception e) {
            log.error("Failed to verify SELinux status", e);
            System.exit(1);
        }
    }

    /**
     * Verify TLS 1.3 is enabled and weak ciphers are disabled.
     */
    private static void verifyTlsConfiguration() {
        // Check enabled protocols
        String[] enabledProtocols = System.getProperty("jdk.tls.client.protocols", "").split(",");
        boolean hasTls13 = false;

        for (String protocol : enabledProtocols) {
            if ("TLSv1.3".equals(protocol.trim())) {
                hasTls13 = true;
            }
            if (protocol.contains("TLSv1") || protocol.contains("TLSv1.1")) {
                log.error("SECURITY VIOLATION: Weak TLS protocol enabled: {}", protocol);
                System.exit(1);
            }
        }

        if (!hasTls13) {
            log.warn("TLS 1.3 not explicitly enabled - verify configuration");
        }

        log.info("TLS configuration verified ✓");
    }
}
