# credtrap

[![Java](https://img.shields.io/badge/Java-17%2B-orange?logo=openjdk)](https://openjdk.org/)
[![Build](https://img.shields.io/badge/build-Maven-blue?logo=apachemaven)](https://maven.apache.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-in%20development-lightgrey)]()

A low-interaction honeypot that serves a convincing fake login page, captures
every credential and request an attacker throws at it, and shows the activity
on a live desktop dashboard.

It doesn't authenticate anyone — there's nothing behind the login form. Its
only job is to look real enough to attract credential-stuffing bots and
opportunistic attackers, and log exactly what they try.

![Dashboard screenshot placeholder](docs/screenshot.png)
*(screenshot coming once the GUI is built)*

## Why this exists

Most portfolio security projects are scanners or detectors — tools that look
*outward*. A honeypot flips that: it's a deception tool that sits and waits,
and the interesting engineering problem is making it convincing while keeping
the attack surface it exposes at zero. There's no real backend, no real
filesystem access, and no code path that touches anything other than logging
whatever came in.

## Features

- Serves a static-looking, convincing fake login page over HTTP
- Captures every submitted attempt — username, password, source IP,
  timestamp, user-agent, headers — without ever validating or using it
- Live dashboard (JavaFX): attempt table, attacker IP list, volume-over-time
  chart
- Optional GeoIP lookup for rough attacker location per entry
- Zero external network dependencies for the core server (built on the JDK's
  own HTTP server)

## How it works

1. A lightweight HTTP server serves the decoy login page on a configurable
   port.
2. Any POST to the login endpoint is captured and persisted — the form
   always "fails," regardless of input, so attackers see a normal-looking
   failed login and keep trying.
3. Captured attempts stream into the dashboard in real time and are written
   to a local log/store for later review.

## Project structure

```
credtrap/
├── src/main/java/com/credtrap/
│   ├── core/        HTTP server, request routing
│   ├── model/        Data classes (CapturedAttempt, AttackerSession)
│   ├── logging/       Persistence of captured attempts
│   ├── gui/           JavaFX dashboard
│   └── util/          GeoIP lookup, helpers
├── src/main/resources/  Fake login page assets
└── src/test/java/com/credtrap/
```

## Design decisions worth knowing about

- **No real authentication path exists.** The login form always fails or
  redirects, regardless of input. There is no code path where submitted
  credentials are compared against anything real.
- **Captured input is treated as untrusted at every layer** — logged and
  displayed as data, never interpreted, evaluated, or used to construct
  file paths, commands, or queries.
- **Threat model**: built for safe local or sandboxed demonstration and
  learning. Running it on a public-facing host is possible but out of scope
  for this repo's guarantees — see [Deployment notes](#deployment-notes)
  before doing that.

## Requirements

- Java 17+
- Maven 3.8+

## Getting started

```bash
git clone https://github.com/<your-username>/credtrap.git
cd credtrap
mvn clean package
mvn exec:java
```

Then visit `http://localhost:8080` to see the decoy login page, and launch
the dashboard to watch captured attempts arrive.

*(Exact run instructions will be finalized as the server and GUI land.)*

## Deployment notes

If you point this at a public interface instead of localhost: run it in an
isolated VM or container with no credentials, secrets, or other services
reachable from it, and treat everything it logs as attacker-controlled data
— never render or execute captured input anywhere (e.g. don't paste it into
a shell).

## Status

Early scaffolding — structure and docs first, server and GUI in progress.
See open issues for what's next.

## License

MIT — see [LICENSE](LICENSE).
