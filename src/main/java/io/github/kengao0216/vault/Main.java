package io.github.kengao0216.vault;

import io.javalin.Javalin;


public final class Main {

    private Main() {

    }

    public static void main(String[] args) {
        Javalin app = Javalin.create();

        app.get("/health", ctx -> ctx.result("ok"));

        app.start(7070);
    }
}
