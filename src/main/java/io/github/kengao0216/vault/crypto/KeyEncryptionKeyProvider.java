package io.github.kengao0216.vault.crypto;

/**
 * Wraps and unwraps DEKs under a KEK.
 */
public interface KeyEncryptionKeyProvider {

    /**
     * Encrypts a data encryption key under the KEK
     *
     * @param dek the raw DEK; the caller retains ownership and should zero it afterwards
     * @return an opaque blob that unwrap() can reverse, safe to store next to the ciphertext it protects
     * @throws CryptoException if wrapping failed or no usable KEK is configured
     */
    byte[] wrap(byte[] dek) throws CryptoException;

    /**
     * Recovers a data encryption key from a blob produced by wrap()
     *
     * @param wrappedDek the opaque blob
     * @return the raw DEK; the caller owns it and must zero it after use
     * @throws TamperDetectedException if the blob failed its integrity check aka it was modified in storage
     * @throws CryptoException if unwrapping failed for any other reason
     */
    byte[] unwrap(byte[] wrappedDek) throws CryptoException;
}
