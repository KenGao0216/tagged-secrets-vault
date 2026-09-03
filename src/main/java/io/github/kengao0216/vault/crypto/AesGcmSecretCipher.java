package io.github.kengao0216.vault.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-256-GCM envelope encryption
 */
public final class AesGcmSecretCipher implements SecretCipher {

    private static final int IV_LENGTH_BYTES = 12;

    private static final int GCM_TAG_LENGTH_BITS = 128;

    // AES-256
    private static final int DEK_LENGTH_BYTES = 32;

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    private final SecureRandom random = new SecureRandom();

    private final KeyEncryptionKeyProvider kekProvider;

    public AesGcmSecretCipher(KeyEncryptionKeyProvider kekProvider) {
        this.kekProvider = Objects.requireNonNull(kekProvider, "kekProvider");
    }

    @Override
    public EncryptedPayload encrypt(byte[] plaintext) throws CryptoException {
        Objects.requireNonNull(plaintext, "plaintext");
        if (plaintext.length == 0) {
            throw new CryptoException("plaintext must not be empty");
        }

        byte[] dek = new byte[DEK_LENGTH_BYTES];
        random.nextBytes(dek);

        try {
            byte[] iv = new byte[IV_LENGTH_BYTES];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(dek, "AES"),
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));

            byte[] ciphertext = cipher.doFinal(plaintext);

            byte[] wrappedDek = kekProvider.wrap(dek);

            return new EncryptedPayload(iv, ciphertext, wrappedDek);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("failed to encrypt secret", e);
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }

    @Override
    public byte[] decrypt(EncryptedPayload payload) throws CryptoException {
        Objects.requireNonNull(payload, "payload");

        byte[] dek = kekProvider.unwrap(payload.wrappedDek());

        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(dek, "AES"),
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, payload.iv()));

            return cipher.doFinal(payload.ciphertext());
        } catch (AEADBadTagException e) {
            // The authentication tag did not match. The ciphertext, IV, or associated data was modified after it was written
            throw new TamperDetectedException("stored data failed its integrity check", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("failed to decrypt secret", e);
        } finally {
            Arrays.fill(dek, (byte) 0);
        }
    }
}
