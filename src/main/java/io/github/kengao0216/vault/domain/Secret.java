package io.github.kengao0216.vault.domain;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

/**
 * An encrypted secret and its metadata.
 */
public record Secret(
        UUID id,
        String name,
        byte[] ciphertext,
        Map<String, String> tags,
        Instant createdAt,
        Instant expiresAt) {

    public Secret {
        Objects.requireNonNull(id, "secret id");
        Objects.requireNonNull(name, "secret name");
        Objects.requireNonNull(ciphertext, "ciphertext");
        Objects.requireNonNull(tags, "tags");
        Objects.requireNonNull(createdAt, "createdAt");
        
        if (ciphertext.length == 0) {throw new IllegalArgumentException("ciphertext must not be empty");}
        ciphertext = ciphertext.clone();

        Map<String, String> validated = new HashMap<>();
        tags.forEach((k, v) -> {
            Tag tag = new Tag(k, v); //validate Tag
            validated.put(tag.key(), tag.value());
        });
        tags = Map.copyOf(validated);


        if(name.isBlank()) {throw new IllegalArgumentException("secret name must not be blank");}
        if (expiresAt != null && expiresAt.isBefore(createdAt)) { 
            throw new IllegalArgumentException("expiresAt cannot precede createdAt");
        }

        // expiresAt intentionally nullable for now
    }

    @Override
    public byte[] ciphertext(){
        return ciphertext.clone();
    }

    @Override 
    public String toString(){
        return "Secret {" + 
        "id=" + id + 
        ", name='" + name +"'" + 
        ", ciphertextLength=" + ciphertext.length+
        ", tagKeys=" + tags.keySet() +
        ", createdAt=" + createdAt + 
        ", expiresAt=" + expiresAt + "}";
    }

    @Override
    public boolean equals(Object obj){
        if(this == obj) return true;
        if(!(obj instanceof Secret other)) return false;
        return id.equals(other.id);
    }

    @Override
    public int hashCode() {
        return id.hashCode();
    }

}
