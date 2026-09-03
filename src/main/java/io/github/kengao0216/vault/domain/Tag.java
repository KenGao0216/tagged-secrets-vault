package io.github.kengao0216.vault.domain;

import java.util.Objects;

/**
 * A single key-value pair of secret metadata, tags are case sensitive
 */
public record Tag(String key, String value) {

    public Tag {
        Objects.requireNonNull(key, "tag key");
        Objects.requireNonNull(value, "tag value");
        if (key.isBlank()) {
            throw new IllegalArgumentException("tag key must not be blank");
        }
        if (value.isBlank()) {
            throw new IllegalArgumentException("tag value must not be blank");
        }
    }
}
