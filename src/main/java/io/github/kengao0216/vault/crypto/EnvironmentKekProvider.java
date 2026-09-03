package io.github.kengao0216.vault.crypto;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Holds the KEK in process memory, loaded from an env var containing a Base64-encoded 32-byte key, and wraps DEKs with local AES-256-GCM
 */
public final class EnvironmentKekProvider implements KeyEncryptionKeyProvider {

    public static final String KEK_ENV_VAR = "VAULT_KEK";

    //AES-256
    private static final int KEK_LENGTH_BYTES = 32;

    private static final int IV_LENGTH_BYTES = 12;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_TAG_LENGTH_BYTES = GCM_TAG_LENGTH_BITS / 8;
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";

    //Shortest blob that could possibly be well-formed
    private static final int MIN_WRAPPED_LENGTH = IV_LENGTH_BYTES + GCM_TAG_LENGTH_BYTES;

    /** Thread-safe and OS-seeded, so it is safe as a field. A Cipher is not — see wrap(). */
    private final SecureRandom random = new SecureRandom();

    private final SecretKey kek;

    /**
     * Loads and validates the KEK
     * @throws CryptoException if the variable is unset, undecodable, or the wrong length
     */
    public EnvironmentKekProvider() throws CryptoException {
        String encoded = System.getenv(KEK_ENV_VAR);
        if (encoded == null || encoded.isBlank()) { 
            throw new CryptoException(KEK_ENV_VAR + " is not set");
        }

        byte[] raw;
        try {
            raw = Base64.getDecoder().decode(encoded.trim());
        } catch (IllegalArgumentException e) {
            throw new CryptoException(KEK_ENV_VAR + " is not valid Base64");
        }

        if (raw.length != KEK_LENGTH_BYTES) {
            int actual = raw.length;
            Arrays.fill(raw, (byte) 0);
            throw new CryptoException(
                    KEK_ENV_VAR + " must decode to " + KEK_LENGTH_BYTES + " bytes, got " + actual);
        }

        this.kek = new SecretKeySpec(raw, "AES");
        Arrays.fill(raw, (byte) 0);
    }

    @Override
    public byte[] wrap(byte[] dek) throws CryptoException {
        if (dek == null || dek.length == 0) {
            throw new CryptoException("DEK must not be empty");
        }

        byte[] iv = new byte[IV_LENGTH_BYTES];
        random.nextBytes(iv);

        try {

            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, kek, new GCMParameterSpec(GCM_TAG_LENGTH_BITS, iv));
            byte[] wrapped = cipher.doFinal(dek);

            byte[] blob = new byte[iv.length + wrapped.length];
            System.arraycopy(iv, 0, blob, 0, iv.length);
            System.arraycopy(wrapped, 0, blob, iv.length, wrapped.length);
            return blob;
        } catch (GeneralSecurityException e) {
            throw new CryptoException("failed to wrap DEK", e);
        }
    }

    @Override
    public byte[] unwrap(byte[] wrappedDek) throws CryptoException {
        if (wrappedDek == null || wrappedDek.length < MIN_WRAPPED_LENGTH) {
            throw new CryptoException("wrapped DEK is malformed");
        }

        try {
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);

            cipher.init(Cipher.DECRYPT_MODE, kek,
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, wrappedDek, 0, IV_LENGTH_BYTES));
            return cipher.doFinal(wrappedDek, IV_LENGTH_BYTES, wrappedDek.length - IV_LENGTH_BYTES);
        } catch (AEADBadTagException e) {
            // The authentication tag did not match: blob was modified after it was written

            throw new TamperDetectedException("stored data failed its integrity check", e);
        } catch (GeneralSecurityException e) {
            throw new CryptoException("failed to unwrap DEK", e);
        }
    }
}
