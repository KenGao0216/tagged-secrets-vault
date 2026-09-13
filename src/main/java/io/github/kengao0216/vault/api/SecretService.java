package io.github.kengao0216.vault.api;

import io.github.kengao0216.vault.crypto.CryptoException;
import io.github.kengao0216.vault.crypto.EncryptedPayload;
import io.github.kengao0216.vault.crypto.SecretCipher;
import io.github.kengao0216.vault.domain.Secret;
import io.github.kengao0216.vault.domain.SecretScope;
import io.github.kengao0216.vault.domain.Tag;
import io.github.kengao0216.vault.storage.StorageException;
import io.github.kengao0216.vault.storage.SecretRepository;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Instant;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Everything the routes do, minus HTTP: encrypt on the way in, apply the caller's scope, decrypt on
 * the way out. No Javalin types appear here, so it can be tested without starting a server, and the
 * HTTP layer is reduced to parsing requests and choosing status codes.
 *
 * <p><b>Every read takes a {@link SecretScope}, and there is no overload without one.</b> That is
 * the "already-scoped view" Step 5 asks for before any RBAC exists. Nothing in this class can reach
 * a secret without saying whose view it is reading through. When Step 7 supplies real scopes, the
 * enforcement is already in place and the only change is where the scope comes from.
 */
public final class SecretService {

    private final SecretRepository repository;
    private final SecretCipher cipher;
    private final Clock clock;

    public SecretService(SecretRepository repository, SecretCipher cipher) {
        this(repository, cipher, Clock.systemUTC());
    }

    SecretService(SecretRepository repository, SecretCipher cipher, Clock clock) {
        this.repository = Objects.requireNonNull(repository, "repository");
        this.cipher = Objects.requireNonNull(cipher, "cipher");
        this.clock = Objects.requireNonNull(clock, "clock");
    }

    /**
     * Encrypts and stores a new secret.
     *
     * @throws InvalidRequestException if the name, value, tags or expiry are unusable
     * @throws ForbiddenException if the tags would place the secret outside the caller's scope
     */
    public SecretMetadata create(SecretScope scope, String name, String value,
            Map<String, String> tags, Instant expiresAt) throws StorageException, CryptoException {
        Objects.requireNonNull(scope, "scope");

        if (name == null || name.isBlank()) {
            throw new InvalidRequestException("name is required");
        }
        if (value == null || value.isEmpty()) {
            throw new InvalidRequestException("value is required");
        }
        Map<String, String> validTags = validateTags(tags == null ? Map.of() : tags);

        Instant now = clock.instant();
        if (expiresAt != null && !expiresAt.isAfter(now)) {
            throw new InvalidRequestException("expiresAt must be in the future");
        }

        if (!scope.permits(validTags)) {
            throw new ForbiddenException("the secret's tags are outside the caller's scope");
        }

        UUID id = UUID.randomUUID();

        byte[] plaintext = value.getBytes(StandardCharsets.UTF_8);
        EncryptedPayload payload;
        try {
            payload = cipher.encrypt(plaintext);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }

        Secret secret = new Secret(id, name, payload.toBytes(), validTags, now, expiresAt);
        repository.save(secret);
        return SecretMetadata.from(secret);
    }

    /**
     * Lists secrets matching filters, within the caller's scope.
     *
     * @throws InvalidRequestException if a filter is malformed, or if an unrestricted caller gives
     *     no filters at all
     */
    public List<SecretMetadata> find(SecretScope scope, Map<String, String> filters)
            throws StorageException {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(filters, "filters");

        Optional<Map<String, String>> effective;
        try {
            effective = scope.narrow(filters);
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new InvalidRequestException("tag filters must have non-blank keys and values");
        }

        if (effective.isEmpty()) {
            return List.of();
        }
        if (effective.get().isEmpty()) {
            throw new InvalidRequestException("at least one tag filter is required");
        }

        return repository.findByTags(effective.get()).stream()
                .map(SecretMetadata::from)
                .toList();
    }

    public Optional<SecretMetadata> describe(SecretScope scope, UUID id) throws StorageException {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(id, "id");
        return repository.findByIdWithTags(id, scope.requiredTags()).map(SecretMetadata::from);
    }

    /**
     * Decrypts one secret's value, or empty if it does not exist / is outside the scope.
     */
    public Optional<String> readValue(SecretScope scope, UUID id)
            throws StorageException, CryptoException {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(id, "id");

        Optional<Secret> secret = repository.findByIdWithTags(id, scope.requiredTags());
        if (secret.isEmpty()) {
            return Optional.empty();
        }

        byte[] plaintext = cipher.decrypt(EncryptedPayload.fromBytes(secret.get().ciphertext()));
        try {
            return Optional.of(new String(plaintext, StandardCharsets.UTF_8));
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static Map<String, String> validateTags(Map<String, String> tags) {
        Map<String, String> valid = new HashMap<>();
        try {
            tags.forEach((key, tagValue) -> {
                Tag tag = new Tag(key, tagValue);
                valid.put(tag.key(), tag.value());
            });
        } catch (IllegalArgumentException | NullPointerException e) {
            throw new InvalidRequestException("tags must have non-blank keys and values");
        }
        return Map.copyOf(valid);
    }
}
