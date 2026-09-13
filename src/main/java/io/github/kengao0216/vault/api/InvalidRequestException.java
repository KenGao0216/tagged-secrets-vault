package io.github.kengao0216.vault.api;

/**
 * The request is malformed. Mapped to 400.
 */
public class InvalidRequestException extends RuntimeException {

    public InvalidRequestException(String message) {
        super(message);
    }
}
