package io.github.kengao0216.vault;

import io.github.kengao0216.vault.api.SecretService;
import io.github.kengao0216.vault.api.UnauthenticatedScopeResolver;
import io.github.kengao0216.vault.api.VaultApi;
import io.github.kengao0216.vault.crypto.AesGcmSecretCipher;
import io.github.kengao0216.vault.crypto.CryptoException;
import io.github.kengao0216.vault.crypto.EnvironmentKekProvider;
import io.github.kengao0216.vault.storage.JdbcSecretRepository;
import io.github.kengao0216.vault.storage.StorageException;
import java.lang.System.Logger.Level;
import java.nio.file.Path;

public final class Main {

    private static final System.Logger LOG = System.getLogger(Main.class.getName());

    private static final String BIND_ADDRESS = "127.0.0.1";
    private static final int PORT = 7070;

    private static final Path DATABASE_FILE = Path.of("vault.db");

    private Main() {
    }

    public static void main(String[] args) {
        try {

            AesGcmSecretCipher cipher = new AesGcmSecretCipher(new EnvironmentKekProvider());
            JdbcSecretRepository repository = new JdbcSecretRepository(DATABASE_FILE);
            SecretService service = new SecretService(repository, cipher);

            LOG.log(Level.WARNING, "API is UNAUTHENTICATED (Step 5): every request has unrestricted "
                    + "access. Listening on " + BIND_ADDRESS + " only.");

            VaultApi.create(service, new UnauthenticatedScopeResolver()).start(BIND_ADDRESS, PORT);
        } catch (CryptoException | StorageException e) {
            System.err.println("vault failed to start: " + e.getMessage());
            System.exit(1);
        }
    }
}
