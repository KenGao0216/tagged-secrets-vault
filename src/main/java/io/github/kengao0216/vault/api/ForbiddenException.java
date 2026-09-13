package io.github.kengao0216.vault.api;

/**
 * The caller may not perform this write. Mapped to 403.
 *Only used where saying "forbidden" discloses nothing about stored data. 
 */
public class ForbiddenException extends RuntimeException {

    public ForbiddenException(String message) {
        super(message);
    }
}
