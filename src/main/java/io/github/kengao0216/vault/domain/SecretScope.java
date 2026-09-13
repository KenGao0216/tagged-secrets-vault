package io.github.kengao0216.vault.domain;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

/**
 * The part of the vault a caller is allowed to see, expressed as tags every visible secret must carry
 */
public record SecretScope(Map<String, String> requiredTags) {

    private static final SecretScope UNRESTRICTED = new SecretScope(Map.of());

    public SecretScope {
        Objects.requireNonNull(requiredTags, "requiredTags");
        Map<String, String> validated = new HashMap<>();
        requiredTags.forEach((key, value) -> {
            Tag tag = new Tag(key, value);
            validated.put(tag.key(), tag.value());
        });
        requiredTags = Map.copyOf(validated);
    }

    public static SecretScope unrestricted() {
        return UNRESTRICTED;
    }

    public boolean isUnrestricted() {
        return requiredTags.isEmpty();
    }

    /** True if a secret carrying tags is inside this scope. */
    public boolean permits(Map<String, String> tags) {
        Objects.requireNonNull(tags, "tags");
        return requiredTags.entrySet().stream()
                .allMatch(required -> required.getValue().equals(tags.get(required.getKey())));
    }

    /**
     * Combines the caller's own filters with this scope into the filters a query should actually
     * run with.
     *
     * the scope always wins if there is a disagreement
     *
     * @return the merged filters, or empty if the caller's filters contradict the scope
     */
    public Optional<Map<String, String>> narrow(Map<String, String> callerFilters) {
        Objects.requireNonNull(callerFilters, "callerFilters");

        Map<String, String> merged = new HashMap<>();
        callerFilters.forEach((key, value) -> {
            Tag tag = new Tag(key, value); 
            merged.put(tag.key(), tag.value());
        });

        for (Map.Entry<String, String> required : requiredTags.entrySet()) {
            String callerValue = merged.putIfAbsent(required.getKey(), required.getValue());
            if (callerValue != null && !callerValue.equals(required.getValue())) {
                return Optional.empty();
            }
        }
        return Optional.of(Map.copyOf(merged));
    }
}
