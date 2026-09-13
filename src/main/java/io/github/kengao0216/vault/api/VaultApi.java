package io.github.kengao0216.vault.api;

import com.fasterxml.jackson.core.StreamReadFeature;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.github.kengao0216.vault.crypto.TamperDetectedException;
import io.javalin.Javalin;
import io.javalin.http.Context;
import io.javalin.json.JavalinJackson;
import java.lang.System.Logger.Level;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * HTTP routes for the vault.
 */
public final class VaultApi {

    private static final System.Logger LOG = System.getLogger(VaultApi.class.getName());
    private static final ErrorResponse NOT_FOUND = new ErrorResponse("secret not found");
    private static final ErrorResponse INTERNAL_ERROR = new ErrorResponse("internal error");
    private static final long MAX_REQUEST_BYTES = 64 * 1024;

    private VaultApi() {
    }

    public static Javalin create(SecretService service, ScopeResolver scopes) {
        Objects.requireNonNull(service, "service");
        Objects.requireNonNull(scopes, "scopes");

        Javalin app = Javalin.create(config -> {
            config.jsonMapper(new JavalinJackson(strictJsonMapper(), false));
            config.http.maxRequestSize = MAX_REQUEST_BYTES;
            config.showJavalinBanner = false;
        });

        app.before(ctx -> ctx.header("Cache-Control", "no-store"));

        app.get("/health", ctx -> ctx.result("ok"));

        app.post("/secrets", ctx -> {
            CreateSecretRequest request = readBody(ctx);
            SecretMetadata created = service.create(scopes.resolve(ctx), request.name(),
                    request.value(), request.tags(), parseExpiry(request.expiresAt()));
            ctx.status(201).header("Location", "/secrets/" + created.id()).json(created);
        });

        app.get("/secrets", ctx -> ctx.json(service.find(scopes.resolve(ctx), tagFilters(ctx))));

        app.get("/secrets/{id}", ctx -> {
            Optional<SecretMetadata> metadata = Optional.empty();
            Optional<UUID> id = parseId(ctx.pathParam("id"));
            if (id.isPresent()) {
                metadata = service.describe(scopes.resolve(ctx), id.get());
            }
            if (metadata.isEmpty()) {
                notFound(ctx);
                return;
            }
            ctx.json(metadata.get());
        });

        app.get("/secrets/{id}/value", ctx -> {
            Optional<UUID> id = parseId(ctx.pathParam("id"));
            Optional<String> value = Optional.empty();
            if (id.isPresent()) {
                value = service.readValue(scopes.resolve(ctx), id.get());
            }
            if (value.isEmpty()) {
                notFound(ctx);
                return;
            }
            ctx.json(new SecretValueResponse(id.get().toString(), value.get()));
        });

        app.exception(InvalidRequestException.class,
                (e, ctx) -> ctx.status(400).json(new ErrorResponse(e.getMessage())));
        app.exception(ForbiddenException.class,
                (e, ctx) -> ctx.status(403).json(new ErrorResponse(e.getMessage())));

        app.exception(TamperDetectedException.class, (e, ctx) -> {
            LOG.log(Level.ERROR, "INTEGRITY CHECK FAILED on " + ctx.method() + " " + ctx.path()
                    + ": stored secret data has been modified");
            ctx.status(500).json(INTERNAL_ERROR);
        });

        app.exception(Exception.class, (e, ctx) -> {
            LOG.log(Level.ERROR, "request failed: " + ctx.method() + " " + ctx.path(), e);
            ctx.status(500).json(INTERNAL_ERROR);
        });

        return app;
    }

    /*
     * reject anything ambiguous
     */
    static ObjectMapper strictJsonMapper() {
        return JsonMapper.builder()
                .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                .enable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .build();
    }

    private static CreateSecretRequest readBody(Context ctx) {
        CreateSecretRequest request;
        try {
            request = ctx.bodyAsClass(CreateSecretRequest.class);
        } catch (Exception e) {
            throw new InvalidRequestException(
                    "body must be a JSON object with name, value, and optional tags and expiresAt");
        }
        if (request == null) { // the literal body `null` parses successfully to no object
            throw new InvalidRequestException("request body is required");
        }
        return request;
    }

    private static Instant parseExpiry(String expiresAt) {
        if (expiresAt == null) {
            return null;
        }
        try {
            return Instant.parse(expiresAt);
        } catch (DateTimeParseException e) {
            throw new InvalidRequestException("expiresAt must be an ISO-8601 instant, e.g. 2027-01-01T00:00:00Z");
        }
    }

    /**
     * Every query parameter is a tag filter.
     */
    private static Map<String, String> tagFilters(Context ctx) {
        Map<String, String> filters = new HashMap<>();
        for (Map.Entry<String, List<String>> parameter : ctx.queryParamMap().entrySet()) {
            if (parameter.getValue().size() != 1) {
                throw new InvalidRequestException("each tag filter may appear only once");
            }
            filters.put(parameter.getKey(), parameter.getValue().get(0));
        }
        return filters;
    }

    /**
     * Parses a path id
     */
    private static Optional<UUID> parseId(String raw) {
        try {
            UUID id = UUID.fromString(raw);
            return id.toString().equalsIgnoreCase(raw) ? Optional.of(id) : Optional.empty();
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
    }

    private static void notFound(Context ctx) {
        ctx.status(404).json(NOT_FOUND);
    }
}
