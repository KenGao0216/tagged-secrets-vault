package io.github.kengao0216.vault.crypto;

/**
 * Encrypts and decrypts secret values.
 */
public interface SecretCipher {

    /**
     * Encrypts plaintext under a freshly generated DEK
     *
     * @param plaintext; the caller keeps ownership and should zero it when done
     * @return the ciphertext, its IV, and the wrapped DEK
     * @throws CryptoException if encryption could not be performed
     */
    EncryptedPayload encrypt(byte[] plaintext) throws CryptoException;

    /**
     * Recovers the plaintext from a payload produced by encrypt()
     *
     * @param payload (stored ciphertext, IV, and wrapped DEK)
     * @return the recovered plaintext; the caller owns it and should zero it when done
     * @throws TamperDetectedException if the integrity check fails
     * @throws CryptoException if decryption could not be performed for any other reason
     */
    byte[] decrypt(EncryptedPayload payload) throws CryptoException;
}
