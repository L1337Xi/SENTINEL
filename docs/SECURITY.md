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

- ClamAV signature matches are preserved as detections but begin as unverified leads; do not equate signature severity with confirmed infection or malware-assessment confidence.
- File investigation is read-only: it checks file identity/type, hashes, Debian package ownership/integrity and available package-source context. Package evidence can support a likely-false-positive assessment but is not proof of safety.
- Quarantine and permanent deletion are explicit local administrative actions. Quarantine verifies a stored copy and hash before removing the original, uses restricted local permissions, and supports hash-verified restore. Permanent deletion requires the full SHA-256 confirmation phrase.
- Package-managed files, hard-linked files, symlinks, and protected system/package paths are not eligible for quarantine or permanent deletion. Use the OS package manager for package-managed software.
- Keep the backend loopback-only: these response endpoints are not authenticated for remote use and must never be exposed to a LAN or the internet.
