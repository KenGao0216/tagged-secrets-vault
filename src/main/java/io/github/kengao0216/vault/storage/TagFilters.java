package io.github.kengao0216.vault.storage;

import io.github.kengao0216.vault.domain.Tag;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

final class TagFilters {

    private TagFilters() {
    }

    /**
     * Returns an immutable, validated copy of 'filters'
     */
    static Map<String, String> validated(Map<String, String> filters) {
        Objects.requireNonNull(filters, "tagFilters");
        if (filters.isEmpty()) {
            throw new IllegalArgumentException("at least one tag filter is required");
        }
        Map<String, String> copy = new LinkedHashMap<>();
        filters.forEach((key, value) -> {
            Tag tag = new Tag(key, value);
            copy.put(tag.key(), tag.value());
        });
        return Map.copyOf(copy);
    }
}
