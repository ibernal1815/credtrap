package com.credtrap.core;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/**
 * Serves the static decoy login page on GET requests.
 *
 * <p>If the request includes {@code ?error=1} (which {@link CaptureHandler}
 * redirects to after every submission), the page renders with its error
 * banner visible — this is what makes a failed attempt look like a normal
 * failed login rather than a dead end, which is what keeps attackers
 * retrying instead of moving on immediately.
 */
public final class LoginPageHandler implements HttpHandler {

    private final String pageTemplate;

    public LoginPageHandler() {
        this.pageTemplate = loadTemplate();
    }

    private static String loadTemplate() {
        try (InputStream in = LoginPageHandler.class.getResourceAsStream("/login.html")) {
            if (in == null) {
                throw new IllegalStateException("login.html not found on classpath");
            }
            return new String(in.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to load login.html", e);
        }
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"GET".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        boolean showError = exchange.getRequestURI().getQuery() != null
                && exchange.getRequestURI().getQuery().contains("error=1");

        String body = showError
                ? pageTemplate.replace("VISIBLE_CLASS", "visible")
                : pageTemplate.replace("VISIBLE_CLASS", "");

        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        exchange.sendResponseHeaders(200, bytes.length);
        try (var os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }
}
