package io.github.kengao0216.vault.storage;

import io.github.kengao0216.vault.domain.Secret;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.sql.Types;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

/**
 * Stores secrets in a SQLite file using plain JDBC.
 */
public final class JdbcSecretRepository implements SecretRepository {

    private static final String CREATE_SECRETS_TABLE = """
            CREATE TABLE IF NOT EXISTS secrets (
                id          TEXT    NOT NULL PRIMARY KEY,
                name        TEXT    NOT NULL,
                ciphertext  BLOB    NOT NULL,
                created_at  INTEGER NOT NULL,
                expires_at  INTEGER
            ) STRICT""";

    private static final String CREATE_TAGS_TABLE = """
            CREATE TABLE IF NOT EXISTS secret_tags (
                secret_id  TEXT NOT NULL REFERENCES secrets (id),
                tag_key    TEXT NOT NULL,
                tag_value  TEXT NOT NULL,
                PRIMARY KEY (secret_id, tag_key)
            ) STRICT""";

    private static final String CREATE_TAG_LOOKUP_INDEX =
            "CREATE INDEX IF NOT EXISTS idx_secret_tags_lookup ON secret_tags (tag_key, tag_value)";

    private static final String INSERT_SECRET = """
            INSERT INTO secrets (id, name, ciphertext, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (id) DO NOTHING""";

    private static final String INSERT_TAG =
            "INSERT INTO secret_tags (secret_id, tag_key, tag_value) VALUES (?, ?, ?)";

    private static final String SELECT_SECRETS_WITH_TAGS = """
            SELECT s.id, s.name, s.ciphertext, s.created_at, s.expires_at, t.tag_key, t.tag_value
            FROM secrets s
            LEFT JOIN secret_tags t ON t.secret_id = s.id
            """;

    private static final String FIND_BY_ID = SELECT_SECRETS_WITH_TAGS + "WHERE s.id = ?";

    private static final String TAG_MATCH_CLAUSE = "(tag_key = ? AND tag_value = ?)";

    private static final long NANOS_PER_SECOND = 1_000_000_000L;

    private final String jdbcUrl;

    /**
     * Opens /creates the database and ensures the schema.
     *
     * @throws StorageException if the database cannot be opened or the schema cannot be created
     */
    public JdbcSecretRepository(Path databaseFile) throws StorageException {
        Objects.requireNonNull(databaseFile, "databaseFile");
        this.jdbcUrl = "jdbc:sqlite:" + databaseFile.toAbsolutePath();

        try (Connection conn = openConnection();
             Statement statement = conn.createStatement()) {
            statement.execute(CREATE_SECRETS_TABLE);
            statement.execute(CREATE_TAGS_TABLE);
            statement.execute(CREATE_TAG_LOOKUP_INDEX);
        } catch (SQLException e) {
            throw new StorageException("failed to initialise the secrets database", e);
        }
    }

    @Override
    public void save(Secret secret) throws StorageException {
        Objects.requireNonNull(secret, "secret");

        try (Connection conn = openConnection()) {
            conn.setAutoCommit(false);
            try {
                insertSecretRow(conn, secret);
                insertTagRows(conn, secret);
                conn.commit();
            } catch (SQLException | StorageException | RuntimeException e) {
                rollbackQuietly(conn, e);
                throw e;
            }
        } catch (SQLException e) {
            throw new StorageException("failed to save secret", e);
        }
    }

    @Override
    public Optional<Secret> findById(UUID id) throws StorageException {
        Objects.requireNonNull(id, "id");

        try (Connection conn = openConnection();
             PreparedStatement statement = conn.prepareStatement(FIND_BY_ID)) {
            statement.setString(1, id.toString());
            try (ResultSet rows = statement.executeQuery()) {
                List<Secret> found = readSecrets(rows);
                return found.isEmpty() ? Optional.empty() : Optional.of(found.get(0));
            }
        } catch (SQLException e) {
            throw new StorageException("failed to read secret", e);
        }
    }

    @Override
    public Optional<Secret> findByIdWithTags(UUID id, Map<String, String> requiredTags)
            throws StorageException {
        Objects.requireNonNull(id, "id");
        Objects.requireNonNull(requiredTags, "requiredTags");
        if (requiredTags.isEmpty()) {
            return findById(id);
        }
        Map<String, String> filters = TagFilters.validated(requiredTags);

        String sql = SELECT_SECRETS_WITH_TAGS
                + "WHERE s.id = ? AND s.id IN (" + tagMatchSubquery(filters.size()) + ")";

        try (Connection conn = openConnection();
             PreparedStatement statement = conn.prepareStatement(sql)) {
            statement.setString(1, id.toString());
            bindTagMatch(statement, 2, filters);

            try (ResultSet rows = statement.executeQuery()) {
                List<Secret> found = readSecrets(rows);
                return found.isEmpty() ? Optional.empty() : Optional.of(found.get(0));
            }
        } catch (SQLException e) {
            throw new StorageException("failed to read secret", e);
        }
    }

    @Override
    public List<Secret> findByTags(Map<String, String> tagFilters) throws StorageException {
        Map<String, String> filters = TagFilters.validated(tagFilters);

        String sql = SELECT_SECRETS_WITH_TAGS
                + "WHERE s.id IN (" + tagMatchSubquery(filters.size()) + ") "
                + "ORDER BY s.id";

        try (Connection conn = openConnection();
             PreparedStatement statement = conn.prepareStatement(sql)) {
            bindTagMatch(statement, 1, filters);

            try (ResultSet rows = statement.executeQuery()) {
                return readSecrets(rows);
            }
        } catch (SQLException e) {
            throw new StorageException("failed to query secrets by tag", e);
        }
    }

    /**
     * helpers
     */
    private static String tagMatchSubquery(int filterCount) {
        return "SELECT secret_id FROM secret_tags WHERE "
                + String.join(" OR ", Collections.nCopies(filterCount, TAG_MATCH_CLAUSE))
                + " GROUP BY secret_id HAVING COUNT(*) = ?";
    }

    private static void bindTagMatch(PreparedStatement statement, int firstIndex,
            Map<String, String> filters) throws SQLException {
        int parameter = firstIndex;
        for (Map.Entry<String, String> filter : filters.entrySet()) {
            statement.setString(parameter++, filter.getKey());
            statement.setString(parameter++, filter.getValue());
        }
        statement.setInt(parameter, filters.size());
    }

    private static void insertSecretRow(Connection conn, Secret secret)
            throws SQLException, StorageException {
        try (PreparedStatement statement = conn.prepareStatement(INSERT_SECRET)) {
            statement.setString(1, secret.id().toString());
            statement.setString(2, secret.name());
            statement.setBytes(3, secret.ciphertext());
            statement.setLong(4, toEpochNanos(secret.createdAt()));
            if (secret.expiresAt() == null) {
                statement.setNull(5, Types.INTEGER);
            } else {
                statement.setLong(5, toEpochNanos(secret.expiresAt()));
            }

            if (statement.executeUpdate() == 0) {
                throw new DuplicateSecretException(secret.id());
            }
        }
    }

    private static void insertTagRows(Connection conn, Secret secret) throws SQLException {
        if (secret.tags().isEmpty()) {
            return;
        }
        try (PreparedStatement statement = conn.prepareStatement(INSERT_TAG)) {
            for (Map.Entry<String, String> tag : secret.tags().entrySet()) {
                statement.setString(1, secret.id().toString());
                statement.setString(2, tag.getKey());
                statement.setString(3, tag.getValue());
                statement.addBatch();
            }
            statement.executeBatch();
        }
    }

    /**
     * Rebuilds Secrets from joined rows
     */
    private static List<Secret> readSecrets(ResultSet rows) throws SQLException, StorageException {
        Map<String, SecretRow> byId = new LinkedHashMap<>();

        while (rows.next()) {
            String id = rows.getString("id");
            SecretRow row = byId.get(id);
            if (row == null) {
                long createdAt = rows.getLong("created_at");
                long expiresAt = rows.getLong("expires_at");
                Long expiresAtOrNull = rows.wasNull() ? null : expiresAt;

                row = new SecretRow(id, rows.getString("name"), rows.getBytes("ciphertext"),
                        createdAt, expiresAtOrNull);
                byId.put(id, row);
            }

            String tagKey = rows.getString("tag_key");
            if (tagKey != null) {
                row.tags.put(tagKey, rows.getString("tag_value"));
            }
        }

        List<Secret> secrets = new ArrayList<>(byId.size());
        for (SecretRow row : byId.values()) {
            secrets.add(row.toSecret());
        }
        return secrets;
    }

    /** Mutable accumulator used only while reading rows */
    private static final class SecretRow {
        private final String id;
        private final String name;
        private final byte[] ciphertext;
        private final long createdAtNanos;
        private final Long expiresAtNanos;
        private final Map<String, String> tags = new HashMap<>();

        SecretRow(String id, String name, byte[] ciphertext, long createdAtNanos, Long expiresAtNanos) {
            this.id = id;
            this.name = name;
            this.ciphertext = ciphertext;
            this.createdAtNanos = createdAtNanos;
            this.expiresAtNanos = expiresAtNanos;
        }

        Secret toSecret() throws StorageException {
            try {
                return new Secret(
                        UUID.fromString(id),
                        name,
                        ciphertext,
                        tags,
                        fromEpochNanos(createdAtNanos),
                        expiresAtNanos == null ? null : fromEpochNanos(expiresAtNanos));
            } catch (IllegalArgumentException e) {
                throw new StorageException("stored secret failed validation", e);
            }
        }
    }

    private static long toEpochNanos(Instant instant) throws StorageException {
        try {
            return Math.addExact(Math.multiplyExact(instant.getEpochSecond(), NANOS_PER_SECOND),
                    instant.getNano());
        } catch (ArithmeticException e) {
            throw new StorageException("timestamp outside the storable range (1677-2262)", e);
        }
    }

    private static Instant fromEpochNanos(long epochNanos) {
        return Instant.ofEpochSecond(0, epochNanos);
    }

    private Connection openConnection() throws SQLException {
        Connection conn = DriverManager.getConnection(jdbcUrl);
        try (Statement statement = conn.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
        } catch (SQLException e) {
            closeQuietly(conn, e);
            throw e;
        }
        return conn;
    }

    private static void rollbackQuietly(Connection conn, Exception original) {
        try {
            conn.rollback();
        } catch (SQLException rollbackFailure) {
            original.addSuppressed(rollbackFailure);
        }
    }

    private static void closeQuietly(Connection conn, Exception original) {
        try {
            conn.close();
        } catch (SQLException closeFailure) {
            original.addSuppressed(closeFailure);
        }
    }
}
