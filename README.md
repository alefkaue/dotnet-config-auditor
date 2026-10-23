# .NET Configuration Auditor

**C# · offline defensive analysis · original personal portfolio project**

Inspect a local appsettings-style JSON layer, preserving environment context and excluding setting values from reports.

[Português](README.pt-BR.md) · [Design and limits](docs/design.md) · [Executed example output](docs/demo-output.txt)

## Run and test

.NET 10 SDK. Uses only the standard framework; no NuGet package dependencies. Tests use a dependency-free executable regression harness with a nonzero failure exit, not a fabricated dotnet-test count.

```console
dotnet run --project tests/ConfigAudit.Tests -c Release
dotnet run --project src/ConfigAudit -c Release -- examples/appsettings.synthetic.json examples/output Production
```

## Features

- Detects possible inline sensitive settings, verbose logging, detailed errors and broad host filtering.
- Treats plaintext listeners as review items because TLS may terminate at a trusted proxy.
- Rejects case-ambiguous/duplicate keys, bounds depth/input size and accepts common comments/trailing commas.
- JSON/Markdown outputs include source SHA-256 and setting paths, without exporting setting values.

## Evidence and limits

One file is not effective application configuration: environment variables, secrets, command-line providers and overlays are not merged. A named setting is a heuristic, not a validated credential or exploitable issue.

The committed examples/output files come from synthetic local runs. They are not customer results,
professional assessments or demonstrations against third-party systems. Input paths and archive names
can still be sensitive: keep real reports private. No account, service or network configuration is changed.

## Engineering

Parsing, decisions and output are separate from CLI argument handling. Tests cover positive cases,
ambiguous evidence and malformed data. GitHub Actions builds/tests on Windows and Linux with
read-only repository permissions and actions pinned by commit. See docs/tests.txt for the recorded local run.

Built by Alef Kaue Santos Nunes with AI assistance. This does not claim professional experience or
independent vulnerability discovery. MIT covers original code and documentation.

## Reference

- [Official format/API reference](https://learn.microsoft.com/en-us/aspnet/core/fundamentals/configuration/)
