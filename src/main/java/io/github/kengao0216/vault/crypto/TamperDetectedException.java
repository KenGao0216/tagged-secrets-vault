package io.github.kengao0216.vault.crypto;

/**
 * Decryption failed its integrity check: the ciphertext, IV, or associated data was modified after it was written.
 */
public class TamperDetectedException extends CryptoException {

    public TamperDetectedException(String message, Throwable cause) {
        super(message, cause);
    }
}
