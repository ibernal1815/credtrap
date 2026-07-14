package com.credtrap;

import com.credtrap.core.HoneypotServer;
import com.credtrap.logging.FileAttemptLogger;

import java.nio.file.Path;

/**
 * Standalone entry point: starts the honeypot HTTP server on the console,
 * with no GUI. Useful for running headless or for quick local testing while
 * the GUI dashboard is still in progress.
 */
public final class Main {

    private static final int DEFAULT_PORT = 8080;

    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : DEFAULT_PORT;
        Path logFile = Path.of("data", "attempts.jsonl");

        var logger = new FileAttemptLogger(logFile);
        var server = new HoneypotServer(port, logger, attempt ->
                System.out.printf("[credtrap] capture: %s%n", attempt)
        );

        Runtime.getRuntime().addShutdownHook(new Thread(server::stop));

        server.start();
        System.out.printf("[credtrap] listening on http://localhost:%d/login%n", server.getPort());
        System.out.printf("[credtrap] logging attempts to %s%n", logFile.toAbsolutePath());
    }
}
