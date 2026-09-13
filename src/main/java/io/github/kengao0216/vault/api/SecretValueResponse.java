package io.github.kengao0216.vault.api;

/** Body of GET /secrets/{id}/value*/
public record SecretValueResponse(String id, String value) {

    @Override
    public String toString() {
        return "SecretValueResponse{id=" + id + ", value=<redacted>}";
    }
}
