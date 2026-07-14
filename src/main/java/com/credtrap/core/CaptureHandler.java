package com.credtrap.core;

import com.credtrap.logging.AttemptLogger;
import com.credtrap.model.CapturedAttempt;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.Consumer;

/**
 * Handles POSTs from the decoy login form.
 *
 * <p>This is the one handler that touches attacker-controlled input
 * directly, so it follows a few hard rules:
 * <ul>
 *   <li>The submitted body is size-capped before parsing, so a huge POST
 *       can't be used to exhaust memory.</li>
 *   <li>Form values are captured as opaque strings — never decoded further,
 *       never used to build a path/command/query, never echoed back into
 *       the HTML response.</li>
 *   <li>The response is identical (a redirect to the login page with an
 *       error flag) regardless of what was submitted — there is no code
 *       path where input is compared against real credentials.</li>
 *   <li>Logging failures are swallowed inside {@link AttemptLogger}, never
 *       here, so a broken log target can't change what the attacker sees.</li>
 * </ul>
 */
public final class CaptureHandler implements HttpHandler {

    private static final int MAX_BODY_BYTES = 8 * 1024; // generous for a login form, small enough to be safe

    private final AttemptLogger logger;
    private final Consumer<CapturedAttempt> onCapture;

    public CaptureHandler(AttemptLogger logger) {
        this(logger, attempt -> { });
    }

    /**
     * @param logger    persists every captured attempt
     * @param onCapture additional sink for captured attempts, e.g. to feed
     *                  a live GUI dashboard. Called after logging, on the
     *                  handler thread — keep it fast and non-throwing.
     */
    public CaptureHandler(AttemptLogger logger, Consumer<CapturedAttempt> onCapture) {
        this.logger = logger;
        this.onCapture = onCapture;
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        if (!"POST".equalsIgnoreCase(exchange.getRequestMethod())) {
            exchange.sendResponseHeaders(405, -1);
            exchange.close();
            return;
        }

        try {
            Map<String, String> form = parseForm(readBodyBounded(exchange.getRequestBody()));
            CapturedAttempt attempt = new CapturedAttempt(
                    Instant.now(),
                    sourceIp(exchange),
                    form.getOrDefault("username", ""),
                    form.getOrDefault("password", ""),
                    exchange.getRequestHeaders().getFirst("User-Agent"),
                    flattenHeaders(exchange)
            );

            safeLog(attempt);
            safeNotify(attempt);
        } catch (Exception e) {
            // Parsing/logging problems must never surface to the attacker
            // or crash the accept loop — log locally and fall through to
            // the same generic response as a normal failed attempt.
            System.err.println("[credtrap] error handling submission: " + e.getMessage());
        }

        redirectToLoginWithError(exchange);
    }

    private void safeLog(CapturedAttempt attempt) {
        try {
            logger.log(attempt);
        } catch (Exception e) {
            System.err.println("[credtrap] logger threw unexpectedly: " + e.getMessage());
        }
    }

    private void safeNotify(CapturedAttempt attempt) {
        try {
            onCapture.accept(attempt);
        } catch (Exception e) {
            System.err.println("[credtrap] capture listener threw unexpectedly: " + e.getMessage());
        }
    }

    private static void redirectToLoginWithError(HttpExchange exchange) throws IOException {
        exchange.getResponseHeaders().set("Location", "/login?error=1");
        exchange.sendResponseHeaders(303, -1);
        exchange.close();
    }

    private static String sourceIp(HttpExchange exchange) {
        InetSocketAddress remote = exchange.getRemoteAddress();
        return remote == null || remote.getAddress() == null
                ? "unknown"
                : remote.getAddress().getHostAddress();
    }

    private static Map<String, String> flattenHeaders(HttpExchange exchange) {
        Map<String, String> flat = new LinkedHashMap<>();
        exchange.getRequestHeaders().forEach((name, values) -> {
            if (!values.isEmpty()) {
                flat.put(name, values.get(0));
            }
        });
        return flat;
    }

    /**
     * Reads the request body up to {@link #MAX_BODY_BYTES}. Anything beyond
     * the cap is discarded rather than buffered, so an oversized POST can't
     * be used to pressure memory.
     */
    private static byte[] readBodyBounded(InputStream in) throws IOException {
        byte[] buffer = new byte[MAX_BODY_BYTES];
        int total = 0;
        int read;
        while (total < buffer.length && (read = in.read(buffer, total, buffer.length - total)) != -1) {
            total += read;
        }
        byte[] result = new byte[total];
        System.arraycopy(buffer, 0, result, 0, total);
        return result;
    }

    /**
     * Parses {@code application/x-www-form-urlencoded} bodies into a map.
     * Deliberately minimal and defensive: malformed pairs are skipped
     * rather than throwing, since the whole point is to accept whatever an
     * attacker sends without giving them a way to trigger an exception that
     * changes server behavior.
     */
    private static Map<String, String> parseForm(byte[] body) {
        Map<String, String> result = new LinkedHashMap<>();
        String raw = new String(body, StandardCharsets.UTF_8);
        for (String pair : raw.split("&")) {
            if (pair.isEmpty()) {
                continue;
            }
            int eq = pair.indexOf('=');
            if (eq < 0) {
                continue;
            }
            try {
                String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
                String value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
                result.put(key, value);
            } catch (IllegalArgumentException e) {
                // Malformed percent-encoding — skip this pair, keep parsing the rest.
            }
        }
        return result;
    }
}
