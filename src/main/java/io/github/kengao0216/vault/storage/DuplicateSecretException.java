package io.github.kengao0216.vault.storage;

import java.util.UUID;

/**
 * A secret with this id already exists
 */
public class DuplicateSecretException extends StorageException {

    private final UUID id;

    public DuplicateSecretException(UUID id) {
        super("a secret with this id already exists");
        this.id = id;
    }

    public DuplicateSecretException(UUID id, Throwable cause) {
        super("a secret with this id already exists", cause);
        this.id = id;
    }

    public UUID id() {
        return id;
    }
}
