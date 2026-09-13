package io.github.kengao0216.vault.storage;

import io.github.kengao0216.vault.domain.Secret;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Keeps secrets in a map
 */
public final class InMemorySecretRepository implements SecretRepository {

    private final ConcurrentMap<UUID, Secret> secrets = new ConcurrentHashMap<>();

    @Override
    public void save(Secret secret) throws StorageException {
        Objects.requireNonNull(secret, "secret");

        if (secrets.putIfAbsent(secret.id(), secret) != null) {
            throw new DuplicateSecretException(secret.id());
        }
    }

    @Override
    public Optional<Secret> findById(UUID id) {
        Objects.requireNonNull(id, "id");
        return Optional.ofNullable(secrets.get(id));
    }

    @Override
    public Optional<Secret> findByIdWithTags(UUID id, Map<String, String> requiredTags) {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(requiredTags, "requiredTags");
        if (requiredTags.isEmpty()) {
            return findById(id);
        }
        Map<String, String> filters = TagFilters.validated(requiredTags);

        return Optional.ofNullable(secrets.get(id))
                .filter(secret -> matchesAll(secret.tags(), filters));
    }

    @Override
    public List<Secret> findByTags(Map<String, String> tagFilters) {
        Map<String, String> filters = TagFilters.validated(tagFilters);

        return secrets.values().stream()
                .filter(secret -> matchesAll(secret.tags(), filters))
                .toList(); 
    }

    private static boolean matchesAll(Map<String, String> tags, Map<String, String> filters) {
        return filters.entrySet().stream()
                .allMatch(filter -> filter.getValue().equals(tags.get(filter.getKey())));
    }
}
