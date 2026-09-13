package io.github.kengao0216.vault.crypto;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Objects;

/**
 * Everything needed to decrypt one secret, except the KEK
 */
public record EncryptedPayload(byte[] iv, byte[] ciphertext, byte[] wrappedDek) {

    /*
     * Serialized layout:
     *   [1 byte  ] format version, currently 1
     *   [1 byte  ] iv length, n
     *   [n bytes ] iv
     *   [4 bytes ] wrappedDek length, m   (big-endian int)
     *   [m bytes ] wrappedDek
     *   [rest    ] ciphertext, including the GCM tag
     */
    private static final byte FORMAT_VERSION = 1;
    private static final int HEADER_BYTES = 1 + 1 + 4; // version + iv length + wrappedDek length

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

    /** Encodes payload as one self-describing blob */
    public byte[] toBytes() {
        if (iv.length > 0xFF) {
            throw new IllegalStateException("IV too long to encode: " + iv.length);
        }
        return ByteBuffer.allocate(HEADER_BYTES + iv.length + wrappedDek.length + ciphertext.length)
                .put(FORMAT_VERSION)
                .put((byte) iv.length)
                .put(iv)
                .putInt(wrappedDek.length)
                .put(wrappedDek)
                .put(ciphertext)
                .array();
    }

    /**
     * Decodes a blob produced by toBytes()
     *
     * @throws CryptoException if the blob is truncated, has an unknown version, or lengths do not add up
     */
    public static EncryptedPayload fromBytes(byte[] bytes) throws CryptoException {
        if (bytes == null || bytes.length < HEADER_BYTES) {
            throw new CryptoException("encrypted payload is malformed");
        }
        try {
            ByteBuffer buf = ByteBuffer.wrap(bytes);

            byte version = buf.get();
            if (version != FORMAT_VERSION) {
                throw new CryptoException("unsupported encrypted payload version: " + version);
            }

            int ivLength = buf.get() & 0xFF;
            byte[] iv = new byte[ivLength];
            buf.get(iv);

            int wrappedDekLength = buf.getInt();
            if (wrappedDekLength < 0 || wrappedDekLength > buf.remaining()) {
                throw new CryptoException("encrypted payload is malformed");
            }
            byte[] wrappedDek = new byte[wrappedDekLength];
            buf.get(wrappedDek);

            byte[] ciphertext = new byte[buf.remaining()];
            buf.get(ciphertext);

            return new EncryptedPayload(iv, ciphertext, wrappedDek);
        } catch (BufferUnderflowException | IllegalArgumentException e) {
            throw new CryptoException("encrypted payload is malformed", e);
        }
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
