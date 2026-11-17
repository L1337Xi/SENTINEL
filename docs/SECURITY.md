# Security guidance

This is an early development foundation, not a production SOC platform.

- Keep the API and Vite server bound to loopback.
- Do not expose the unauthenticated API to a LAN or the internet.
- Treat all event payloads and future imports as untrusted input.
- Do not execute uploaded files or provide dashboard-driven shell access.
- Store real evidence outside the Git working tree; local data directories are ignored.
- Keep secrets in local environment files and never commit them.
- Preserve original evidence and calculate hashes before analysis when evidence workflows are introduced.
- Review dependency updates and run tests before deploying changes.

Report security issues privately to the repository owner rather than publishing sensitive exploit details.
