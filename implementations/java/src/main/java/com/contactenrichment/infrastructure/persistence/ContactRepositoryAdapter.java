package com.contactenrichment.infrastructure.persistence;

import com.contactenrichment.domain.model.Contact;
import com.contactenrichment.domain.repository.ContactRepository;
import com.contactenrichment.infrastructure.security.SecurityContext;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Adapter implementing domain ContactRepository using Spring Data JPA.
 *
 * Responsibilities:
 * - Translate domain repository interface to Spring Data JPA
 * - Set PostgreSQL session variables for Row-Level Security (RLS)
 * - Log security-relevant operations
 * - Handle optimistic locking exceptions
 *
 * PostgreSQL RLS Example:
 * CREATE POLICY contact_select_policy ON contacts FOR SELECT
 * USING (
 *   confidentiality_level <= current_setting('app.clearance_conf')::int
 *   AND integrity_level <= current_setting('app.clearance_integ')::int
 * );
 */
@Component
@Transactional
@RequiredArgsConstructor
@Slf4j
public class ContactRepositoryAdapter implements ContactRepository {

    private final SpringDataContactRepository springDataRepository;

    @PersistenceContext
    private final EntityManager entityManager;

    /**
     * Set PostgreSQL session variables for RLS enforcement.
     */
    private void applySecurityContext(SecurityContext context) {
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

        log.debug("Applied RLS context: principal={}, clearance={}",
            context.getPrincipalId(),
            context.getClearance());
    }

    @Override
    public Optional<Contact> findById(UUID id, SecurityContext context) {
        applySecurityContext(context);

        Optional<Contact> result = springDataRepository.findById(id);

        if (result.isPresent()) {
            log.info("Contact retrieved: id={}, principal={}",
                id, context.getPrincipalId());
        } else {
            log.debug("Contact not found or access denied: id={}", id);
        }

        return result;
    }

    @Override
    public Optional<Contact> findByEmailHash(byte[] emailHash, SecurityContext context) {
        applySecurityContext(context);

        Optional<Contact> result = springDataRepository.findByCanonicalEmailHash(emailHash);

        if (result.isPresent()) {
            log.info("Contact retrieved by email hash: id={}, principal={}",
                result.get().getId(), context.getPrincipalId());
        }

        return result;
    }

    @Override
    public void save(Contact contact, SecurityContext context) {
        applySecurityContext(context);

        springDataRepository.save(contact);

        log.info("Contact persisted: id={}, version={}, principal={}",
            contact.getId(), contact.getVersion(), context.getPrincipalId());
    }

    @Override
    public void delete(UUID id, SecurityContext context) {
        applySecurityContext(context);

        springDataRepository.deleteById(id);

        log.warn("Contact deleted: id={}, principal={}",
            id, context.getPrincipalId());
    }

    @Override
    public boolean existsByEmailHash(byte[] emailHash, SecurityContext context) {
        applySecurityContext(context);

        return springDataRepository.existsByCanonicalEmailHash(emailHash);
    }
}
