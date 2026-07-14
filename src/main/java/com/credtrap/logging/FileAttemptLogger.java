package com.credtrap.logging;

import com.credtrap.model.CapturedAttempt;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.format.DateTimeFormatter;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Appends each captured attempt as one JSON line to a log file
 * (JSON Lines / JSONL format — easy to tail, easy to parse, no DB needed).
 *
 * <p>Writes are serialized with a lock rather than relying on filesystem
 * append atomicity, since multiple attacker connections can be captured
 * concurrently and interleaved partial writes would corrupt the file.
 *
 * <p>This class does its own minimal JSON string escaping rather than
 * pulling in a JSON library, since the schema is fixed and small — but see
 * {@code escape()} below; if the schema grows, switch to a real JSON writer
 * rather than extending hand-rolled escaping.
 */
public final class FileAttemptLogger implements AttemptLogger {

    private static final DateTimeFormatter TIMESTAMP_FORMAT = DateTimeFormatter.ISO_INSTANT;

    private final Path logFile;
    private final ReentrantLock writeLock = new ReentrantLock();

    public FileAttemptLogger(Path logFile) {
        this.logFile = logFile;
        try {
            Path parent = logFile.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
        } catch (IOException e) {
            throw new UncheckedIOException("Could not create log directory for " + logFile, e);
        }
    }

    @Override
    public void log(CapturedAttempt attempt) {
        String line = toJsonLine(attempt);
        writeLock.lock();
        try {
            Files.writeString(
                    logFile,
                    line + System.lineSeparator(),
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );
        } catch (IOException e) {
            // Never let a logging failure propagate into the request path —
            // print to stderr and move on so the honeypot keeps responding.
            System.err.println("[credtrap] failed to write attempt log: " + e.getMessage());
        } finally {
            writeLock.unlock();
        }
    }

    private String toJsonLine(CapturedAttempt attempt) {
        StringBuilder sb = new StringBuilder();
        sb.append('{');
        sb.append("\"timestamp\":\"").append(TIMESTAMP_FORMAT.format(attempt.getTimestamp())).append("\",");
        sb.append("\"sourceIp\":\"").append(escape(attempt.getSourceIp())).append("\",");
        sb.append("\"username\":\"").append(escape(attempt.getUsername())).append("\",");
        sb.append("\"password\":\"").append(escape(attempt.getPassword())).append("\",");
        sb.append("\"userAgent\":\"").append(escape(attempt.getUserAgent())).append("\",");
        sb.append("\"headers\":{");
        boolean first = true;
        for (Map.Entry<String, String> header : attempt.getHeaders().entrySet()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('"').append(escape(header.getKey())).append("\":\"")
                    .append(escape(header.getValue())).append('"');
        }
        sb.append('}');
        sb.append('}');
        return sb.toString();
    }

    /**
     * Minimal JSON string escaping. Attacker input is arbitrary bytes sent
     * to a login form, so this must handle quotes, backslashes, control
     * characters, and newlines — anything less and a crafted username could
     * break out of the JSON string and corrupt the log line.
     */
    private static String escape(String value) {
        if (value == null) {
            return "";
        }
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '"' -> out.append("\\\"");
                case '\\' -> out.append("\\\\");
                case '\n' -> out.append("\\n");
                case '\r' -> out.append("\\r");
                case '\t' -> out.append("\\t");
                default -> {
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
                }
            }
        }
        return out.toString();
    }
}
