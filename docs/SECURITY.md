# Security guidance

This is an early development foundation, not a production SOC platform.

- Keep the API and Vite server bound to loopback.
- Do not expose the unauthenticated API to a LAN or the internet.
- Treat all event payloads and future imports as untrusted input.
- Do not execute uploaded files or provide dashboard-driven shell access.
- Store real evidence outside the Git working tree; local data directories are ignored.
- Keep secrets in local environment files and never commit them. In particular, never commit the MalwareBazaar API key.
- Host assessment may send bounded SHA-256 values to CIRCL hashlookup and retrieve MalwareBazaar feed metadata when configured. It never uploads file contents or local paths. Disable CIRCL lookups with `SENTINEL_CIRCL_MAX_LOOKUPS=0` when offline or when external hash disclosure is not acceptable.
- Treat CIRCL hashlookup responses as known-file context, not a clean bill of health or a malware verdict.
- Preserve original evidence and calculate hashes before analysis when evidence workflows are introduced.
- Review dependency updates and run tests before deploying changes.

Report security issues privately to the repository owner rather than publishing sensitive exploit details.
