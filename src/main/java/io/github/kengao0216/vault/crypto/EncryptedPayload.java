package io.github.kengao0216.vault.crypto;

import java.util.Arrays;
import java.util.Objects;

/**
 * Everything needed to decrypt one secret, except the KEK
 */
public record EncryptedPayload(byte[] iv, byte[] ciphertext, byte[] wrappedDek) {

    public EncryptedPayload {
        Objects.requireNonNull(iv, "iv");
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(wrappedDek, "wrappedDek");

        if (iv.length == 0) {
            throw new IllegalArgumentException("IV must not be empty");
        }
        if (ciphertext.length == 0 || wrappedDek.length == 0) {
            throw new IllegalArgumentException("ciphertext must not be empty");
        }

        iv = iv.clone();
        ciphertext = ciphertext.clone();
        wrappedDek = wrappedDek.clone();
    }

    @Override
    public byte[] iv() {
        return iv.clone();
    }

    @Override
    public byte[] ciphertext() {
        return ciphertext.clone();
    }

    @Override
    public byte[] wrappedDek() {
        return wrappedDek.clone();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof EncryptedPayload other)) {
            return false;
        }
        return Arrays.equals(iv, other.iv)
                && Arrays.equals(ciphertext, other.ciphertext)
                && Arrays.equals(wrappedDek, other.wrappedDek);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(iv) * 31 + Arrays.hashCode(ciphertext);
    }

    @Override
    public String toString() {
        return "EncryptedPayload{ivLength=" + iv.length
                + ", ciphertextLength=" + ciphertext.length
                + ", wrappedDekLength=" + wrappedDek.length + "}";
    }
}
