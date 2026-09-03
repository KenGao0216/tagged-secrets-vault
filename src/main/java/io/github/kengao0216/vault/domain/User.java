package io.github.kengao0216.vault.domain;

import java.util.Objects;

/**
 * An authenticated principal. caller's identity
 */
public record User(String id, String name, Role role) {

    public User {
        Objects.requireNonNull(id, "user id");
        Objects.requireNonNull(name, "user name");
        Objects.requireNonNull(role, "user role");
        
        if(id.isBlank()) {throw new IllegalArgumentException("id must not be blank"); }
        if(name.isBlank()) {throw new IllegalArgumentException("name must not be blank"); }

    }
}
