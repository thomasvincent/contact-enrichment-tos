package com.contactenrichment.infrastructure.persistence;

import com.contactenrichment.domain.model.Contact;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Spring Data JPA repository for Contact aggregate.
 *
 * Security: PostgreSQL Row-Level Security (RLS) policies enforce MAC at database level.
 * Session variables must be set before queries to activate RLS.
 */
@Repository
public interface SpringDataContactRepository extends JpaRepository<Contact, UUID> {

    /**
     * Find contact by canonical email hash.
     *
     * @param hash SHA-256 hash of canonical email
     * @return Optional contact
     */
    @Query("SELECT c FROM Contact c WHERE c.canonicalEmailHash = :hash")
    Optional<Contact> findByCanonicalEmailHash(@Param("hash") byte[] hash);

    /**
     * Check if contact exists by email hash.
     *
     * @param hash SHA-256 hash of canonical email
     * @return true if exists
     */
    boolean existsByCanonicalEmailHash(byte[] hash);
}
