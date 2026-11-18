# Development roadmap

- [x] Initial FastAPI service and health endpoint
- [x] SQLite-backed event ingestion and retrieval
- [x] React/TypeScript dashboard connected to the API
- [x] Event search and severity filtering
- [x] Initial backend test coverage and CI workflow
- [ ] Authentication, authorization, and secure session management
- [ ] Event source adapters and normalization
- [x] Initial deterministic detection rule and alert lifecycle (open, acknowledged, resolved)
- [ ] Sigma-compatible rule ingestion, validation, and evaluation
- [ ] Correlation, incident cases, and investigation timelines
- [ ] Evidence intake, hashing, metadata, and chain of custody
- [ ] YARA-assisted analysis workflow
- [ ] Offline PCAP analysis and optional Zeek/Suricata integrations
- [x] Append-only local audit records for event ingestion, alert creation, and alert status transitions
- [ ] Audit trail exports, reporting, backup, and restore
- [ ] Packaging, threat modelling, and release hardening

A checked item means the code has been added to the repository; it does not imply an independently audited production release.
