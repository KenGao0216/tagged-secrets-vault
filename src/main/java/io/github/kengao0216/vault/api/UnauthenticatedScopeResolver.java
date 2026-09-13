package io.github.kengao0216.vault.api;

import io.github.kengao0216.vault.domain.SecretScope;
import io.javalin.http.Context;

/**
 * Grants every request unrestricted access, placeholder cuz no auth yet
 */
public final class UnauthenticatedScopeResolver implements ScopeResolver {

    @Override
    public SecretScope resolve(Context ctx) {
        return SecretScope.unrestricted();
    }
}
