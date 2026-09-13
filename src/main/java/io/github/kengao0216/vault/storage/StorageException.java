package io.github.kengao0216.vault.storage;

/**
 * A repository operation could not be completed
 */
public class StorageException extends Exception {

    public StorageException(String message) {
        super(message);
    }

    public StorageException(String message, Throwable cause) {
        super(message, cause);
    }
}
