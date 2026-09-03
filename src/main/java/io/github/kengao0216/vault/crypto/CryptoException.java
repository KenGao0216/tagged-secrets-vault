package io.github.kengao0216.vault.crypto;

/**
 * Something went wrong performing a cryptographic operation.
 */
public class CryptoException extends Exception {

    public CryptoException(String message, Throwable cause) {
        super(message, cause);
    }

    public CryptoException(String message) {
        super(message);
    }
}
