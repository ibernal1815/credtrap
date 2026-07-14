package com.credtrap.model;

import java.time.Instant;
import java.util.Collections;
import java.util.Map;

/**
 * A single captured login attempt against the decoy login page.
 *
 * <p>This is a pure data holder. Nothing in this class validates, decodes,
 * or acts on the captured values — username and password are stored exactly
 * as received and must be treated as untrusted attacker-controlled input by
 * every consumer (logging, GUI, persistence).
 */
public final class CapturedAttempt {

    private final Instant timestamp;
    private final String sourceIp;
    private final String username;
    private final String password;
    private final String userAgent;
    private final Map<String, String> headers;

    public CapturedAttempt(Instant timestamp,
                            String sourceIp,
                            String username,
                            String password,
                            String userAgent,
                            Map<String, String> headers) {
        this.timestamp = timestamp;
        this.sourceIp = sourceIp;
        this.username = username;
        this.password = password;
        this.userAgent = userAgent;
        this.headers = headers == null ? Map.of() : Collections.unmodifiableMap(headers);
    }

    public Instant getTimestamp() {
        return timestamp;
    }

    public String getSourceIp() {
        return sourceIp;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public Map<String, String> getHeaders() {
        return headers;
    }

    @Override
    public String toString() {
        // Deliberately does not include password in a readable form beyond
        // what logging explicitly asks for — callers decide what to persist
        // and where. toString() here is for debugging only.
        return "CapturedAttempt{" +
                "timestamp=" + timestamp +
                ", sourceIp='" + sourceIp + '\'' +
                ", username='" + username + '\'' +
                ", userAgent='" + userAgent + '\'' +
                ", headerCount=" + headers.size() +
                '}';
    }
}
