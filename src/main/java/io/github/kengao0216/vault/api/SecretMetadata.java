package io.github.kengao0216.vault.api;

import io.github.kengao0216.vault.domain.Secret;
import java.util.Map;

/**
 * What the API reveals about a secret
 */
public record SecretMetadata(String id, String name, Map<String, String> tags, String createdAt,
        String expiresAt) {

    static SecretMetadata from(Secret secret) {
        return new SecretMetadata(
                secret.id().toString(),
                secret.name(),
                secret.tags(),
                secret.createdAt().toString(),
                secret.expiresAt() == null ? null : secret.expiresAt().toString());
    }
}
