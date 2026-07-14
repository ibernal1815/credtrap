package com.credtrap.logging;

import com.credtrap.model.CapturedAttempt;

/**
 * Persists captured login attempts.
 *
 * <p>Implementations must not throw on malformed or hostile input — a
 * honeypot's entire purpose is to safely absorb attacker-controlled data, so
 * a logging failure should never take down the server or leak an exception
 * containing raw attacker input back to the client.
 */
public interface AttemptLogger {

    /**
     * Records a captured attempt. Implementations should treat this as
     * fire-and-forget from the caller's perspective — any I/O failure is
     * handled internally (e.g. logged to stderr) rather than propagated,
     * since a logging error must never prevent the server from responding
     * to the attacker or block the accept loop.
     */
    void log(CapturedAttempt attempt);
}
