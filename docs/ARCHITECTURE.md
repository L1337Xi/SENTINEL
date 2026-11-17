# Architecture

SENTINEL starts as a local modular monolith. The browser dashboard communicates with a FastAPI JSON API; the API validates requests and persists normalized event records in SQLite.

## Current request path

`React UI → FastAPI → Pydantic validation → SQLite`

- The API owns validation and persistence.
- SQLite is stored under the backend data directory by default.
- The API binds to loopback in the documented development command.
- CORS is restricted to the local Vite development origins.
- No uploaded file is executed and no shell command endpoint is exposed.

## Boundaries planned for later milestones

Ingestion adapters, normalization, detection rules, correlation, case management, evidence handling, network analysis, and reporting should be separate service modules. Keep source records traceable; do not silently rewrite original evidence.

## Operational caveat

Authentication and authorization are not implemented in this foundation. Do not expose the API or frontend development server to an untrusted network.
