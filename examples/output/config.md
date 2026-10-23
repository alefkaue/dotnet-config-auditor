# .NET configuration review

One local configuration layer only. No environment merge, startup, secret validation, network probing or automatic changes.

Environment: Production

Input SHA-256: `5b57fd425d2ae547d218acdabf9efae53bfbe3cc53f32f600ecc5c4e3a1d6199`

- **medium / BROAD_HOST_FILTER** at $.AllowedHosts: Host filter is broad or empty in this layer. Check effective hosting/proxy configuration and intended hostnames; this alone does not establish Host-header exploitation.

- **medium / DETAILED_ERRORS** at $.DetailedErrors: Detailed errors are enabled in the supplied file. Review environment and framework behavior; production diagnostics should avoid disclosing sensitive detail.

- **medium / VERBOSE_LOGGING** at $.Logging.LogLevel.Default: Verbose logging selected in the supplied configuration layer. Review sinks, access, retention and whether application logging includes sensitive data.

- **review / HTTP_LISTENER_REVIEW** at $.Kestrel.Endpoints.Internal.Url: A plaintext listener is configured. A reverse proxy may terminate TLS legitimately. Verify actual binding, network reachability and trusted-proxy TLS; no reachability check was performed.

- **medium / INLINE_SENSITIVE_SETTING** at $.ConnectionStrings.Example: Possible inline sensitive setting. Its value is intentionally excluded from reports; validity was not tested. Review whether this is a real secret or non-sensitive placeholder. Use an appropriate secret provider for actual credentials.
