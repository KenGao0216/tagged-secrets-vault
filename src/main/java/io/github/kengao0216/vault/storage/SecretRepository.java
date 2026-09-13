package io.github.kengao0216.vault.storage;

import io.github.kengao0216.vault.domain.Secret;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

/**
 * Persistence for secrets
 *
 * This layer stores Secret.ciphertext as opaque bytes. It cannot decrypt them and does not know they are encrypted
 */
public interface SecretRepository {

    /**
     * Stores a new secret
     *
     * @throws DuplicateSecretException if a secret with the same id already exists
     * @throws StorageException if the write failed
     */
    void save(Secret secret) throws StorageException;

    /**
     * Looks up one secret by id.
     *
     * Returns Optional
     */
    Optional<Secret> findById(UUID id) throws StorageException;

    /**
     * Finds every secret carrying all of the given tags     
     * 
     * @throws IllegalArgumentException if tagFilters is empty, or contains a blank key or value
     * @throws NullPointerException if tagFilters contains a null key or value
     */
    List<Secret> findByTags(Map<String, String> tagFilters) throws StorageException;
}
