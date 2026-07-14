package com.credtrap.core;

import com.credtrap.logging.AttemptLogger;
import com.credtrap.model.CapturedAttempt;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

/**
 * Wraps the JDK's built-in {@link HttpServer} to serve the decoy login page
 * and capture submissions.
 *
 * <p>Uses the JDK HTTP server (no external web framework) deliberately: it
 * keeps the dependency tree at zero for the part of this project that
 * directly faces untrusted network input, which matters more here than in
 * a typical app.
 *
 * <p>Each connection is handled on a pooled thread so one slow or
 * misbehaving client (deliberately or not) can't stall others.
 */
public final class HoneypotServer {

    private final HttpServer httpServer;
    private final ExecutorService executor;

    public HoneypotServer(int port, AttemptLogger logger) throws IOException {
        this(port, logger, attempt -> { });
    }

    /**
     * @param onCapture called with every captured attempt, e.g. to feed a
     *                  live dashboard. See {@link CaptureHandler} for the
     *                  threading contract.
     */
    public HoneypotServer(int port, AttemptLogger logger, Consumer<CapturedAttempt> onCapture) throws IOException {
        this.httpServer = HttpServer.create(new InetSocketAddress(port), 0);
        this.executor = Executors.newCachedThreadPool();
        httpServer.setExecutor(executor);

        LoginPageHandler loginPage = new LoginPageHandler();
        CaptureHandler capture = new CaptureHandler(logger, onCapture);

        // The form's action is "/login" for both the page (GET) and the
        // submission (POST), matching a real login endpoint's usual shape.
        // HttpServer routes by path only, so one handler here dispatches
        // by method rather than registering two contexts on the same path.
        httpServer.createContext("/login", exchange -> {
            if ("POST".equalsIgnoreCase(exchange.getRequestMethod())) {
                capture.handle(exchange);
            } else {
                loginPage.handle(exchange);
            }
        });
        httpServer.createContext("/", loginPage);
    }

    public void start() {
        httpServer.start();
    }

    public void stop() {
        httpServer.stop(0);
        executor.shutdownNow();
    }

    public int getPort() {
        return httpServer.getAddress().getPort();
    }
}
