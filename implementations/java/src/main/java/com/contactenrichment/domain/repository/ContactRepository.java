package com.contactenrichment.domain.repository;

import com.contactenrichment.domain.model.Contact;
import com.contactenrichment.infrastructure.security.SecurityContext;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

/**
 * Repository interface for Contact aggregate.
 *
 * <p>Implementations must enforce:
 * <ul>
 *   <li>Row-Level Security based on caller's security clearance</li>
 *   <li>Encryption of all PII fields before storage</li>
 *   <li>Audit event generation for all operations</li>
 *   <li>Domain event publishing after persistence</li>
 * </ul>
 *
 * @author Thomas Vincent
 * @since 1.0.0
 */
public interface ContactRepository {

    /**
     * Find contact by ID with security enforcement.
     *
     * @param id Contact ID
     * @param context Security context of caller
     * @return Contact if found and accessible, empty otherwise
     */
    Optional<Contact> findById(UUID id, SecurityContext context);

    /**
     * Find contact by email hash (for deduplication).
     *
     * @param emailHash SHA-256 hash of email
     * @param context Security context
     * @return Contact if found and accessible
     */
    Optional<Contact> findByEmailHash(byte[] emailHash, SecurityContext context);

    /**
     * Save contact (create or update).
     *
     * <p>Publishes domain events after successful persistence.
     *
     * @param contact Contact to save
     * @param context Security context
     */
    void save(Contact contact, SecurityContext context);

    /**
     * Search contacts matching criteria.
     *
     * <p>Results automatically filtered by caller's security clearance.
     *
     * @param criteria Search criteria
     * @param context Security context
     * @return List of accessible contacts
     */
    List<Contact> findByCriteria(ContactSearchCriteria criteria, SecurityContext context);

    /**
     * Count contacts matching criteria.
     *
     * @param criteria Search criteria
     * @param context Security context
     * @return Count of accessible contacts
     */
    long countByCriteria(ContactSearchCriteria criteria, SecurityContext context);
}
