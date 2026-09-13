package io.github.kengao0216.vault.api;

import java.util.Map;

/**
 * Body of POST/secrets.
 *
 * @param expiresAt optional ISO-8601 instant
 */
public record CreateSecretRequest(String name, String value, Map<String, String> tags, String expiresAt) {

    @Override
    public String toString() {
        return "CreateSecretRequest{name='" + name + "', value=<redacted>, tagKeys="
                + (tags == null ? "[]" : tags.keySet()) + ", expiresAt=" + expiresAt + "}";
    }
}
