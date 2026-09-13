package io.github.kengao0216.vault.api;

import io.github.kengao0216.vault.domain.SecretScope;
import io.javalin.http.Context;

/**
 * Decides which part of the vault an incoming request may see
 */
@FunctionalInterface
public interface ScopeResolver {

    SecretScope resolve(Context ctx);
}
