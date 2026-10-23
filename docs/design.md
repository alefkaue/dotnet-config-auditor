# Design and trust boundaries

Inspect a local appsettings-style JSON layer, preserving environment context and excluding setting values from reports.

- Detects possible inline sensitive settings, verbose logging, detailed errors and broad host filtering.
- Treats plaintext listeners as review items because TLS may terminate at a trusted proxy.
- Rejects case-ambiguous/duplicate keys, bounds depth/input size and accepts common comments/trailing commas.
- JSON/Markdown outputs include source SHA-256 and setting paths, without exporting setting values.

One file is not effective application configuration: environment variables, secrets, command-line providers and overlays are not merged. A named setting is a heuristic, not a validated credential or exploitable issue.

The source snapshot is evidence supplied by the operator, not remote attestation. A metadata flag or heuristic is not proof of an attack. Tests use fixtures constructed by this repository and do not contact external targets. Do not execute or extract untrusted samples as a way to use this tool.
