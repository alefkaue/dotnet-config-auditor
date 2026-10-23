using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
namespace ConfigAudit;

public sealed record Finding(string Rule, string Priority, string JsonPath, string Observation, string Recommendation);
public sealed record Report(int SchemaVersion, string Environment, string InputSha256,
    string Scope, int InspectedLeaves, IReadOnlyList<Finding> Findings);

public static class Auditor
{
    static readonly Regex SecretName = new(@"(?:password|secret|api[_-]?key|token)$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    public static Report Inspect(byte[] bytes, string environment)
    {
        if (bytes.Length > 2_000_000) throw new InvalidDataException("Configuration exceeds 2 MB");
        if (environment is not ("Production" or "Development" or "Unknown")) throw new ArgumentException("Use Production, Development or Unknown");
        using var document = JsonDocument.Parse(bytes, new JsonDocumentOptions { MaxDepth = 32, CommentHandling = JsonCommentHandling.Skip, AllowTrailingCommas = true });
        if (document.RootElement.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Root must be an object");
        var findings = new List<Finding>(); int leaves = 0;
        void Add(string rule, string priority, string path, string observation, string recommendation) => findings.Add(new(rule, priority, path, observation, recommendation));
        void Visit(JsonElement node, string path, string name, bool connectionString)
        {
            if (node.ValueKind == JsonValueKind.Object)
            {
                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                foreach (var property in node.EnumerateObject())
                {
                    if (!seen.Add(property.Name)) throw new InvalidDataException("Duplicate/case-ambiguous key at " + path);
                    Visit(property.Value, path + "." + property.Name, property.Name,
                        connectionString || property.Name.Equals("ConnectionStrings", StringComparison.OrdinalIgnoreCase));
                }
                return;
            }
            if (node.ValueKind == JsonValueKind.Array)
            {
                int index = 0; foreach (var value in node.EnumerateArray()) Visit(value, path + "[" + index++ + "]", name, connectionString);
                return;
            }
            if (++leaves > 10000) throw new InvalidDataException("Too many configuration leaves");
            var valueText = node.ValueKind == JsonValueKind.String ? node.GetString() ?? "" : node.GetRawText();
            bool production = environment == "Production";
            if (node.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(valueText) && (connectionString || SecretName.IsMatch(name)))
            {
                bool placeholder = valueText.StartsWith("env:", StringComparison.OrdinalIgnoreCase)
                    || valueText.StartsWith("${", StringComparison.Ordinal) && valueText.EndsWith('}')
                    || valueText.StartsWith('%') && valueText.EndsWith('%');
                if (!placeholder) Add("INLINE_SENSITIVE_SETTING", production ? "medium" : "review", path,
                    "Possible inline sensitive setting. Its value is intentionally excluded from reports; validity was not tested.",
                    "Review whether this is a real secret or non-sensitive placeholder. Use an appropriate secret provider for actual credentials.");
            }
            if (name.Equals("DetailedErrors", StringComparison.OrdinalIgnoreCase) && node.ValueKind == JsonValueKind.True)
                Add("DETAILED_ERRORS", production ? "medium" : "info", path, "Detailed errors are enabled in the supplied file.", "Review environment and framework behavior; production diagnostics should avoid disclosing sensitive detail.");
            if (name.Equals("AllowedHosts", StringComparison.OrdinalIgnoreCase) && (valueText == "*" || string.IsNullOrWhiteSpace(valueText)))
                Add("BROAD_HOST_FILTER", production ? "medium" : "review", path, "Host filter is broad or empty in this layer.", "Check effective hosting/proxy configuration and intended hostnames; this alone does not establish Host-header exploitation.");
            if (path.Contains(".Logging.", StringComparison.OrdinalIgnoreCase) && valueText is "Trace" or "Debug")
                Add("VERBOSE_LOGGING", production ? "medium" : "info", path, "Verbose logging selected in the supplied configuration layer.", "Review sinks, access, retention and whether application logging includes sensitive data.");
            if (path.Contains(".Kestrel.Endpoints.", StringComparison.OrdinalIgnoreCase) && name.Equals("Url", StringComparison.OrdinalIgnoreCase)
                && valueText.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                Add("HTTP_LISTENER_REVIEW", "review", path, "A plaintext listener is configured. A reverse proxy may terminate TLS legitimately.", "Verify actual binding, network reachability and trusted-proxy TLS; no reachability check was performed.");
        }
        Visit(document.RootElement, "$", "", false);
        return new(1, environment, Convert.ToHexString(SHA256.HashData(bytes)).ToLowerInvariant(),
            "One local configuration layer only. No environment merge, startup, secret validation, network probing or automatic changes.", leaves, findings);
    }
    public static Report Load(string path, string environment)
    {
        using var stream = File.OpenRead(path);
        if (stream.Length > 2_000_000) throw new InvalidDataException("Configuration exceeds 2 MB");
        var bytes = new byte[checked((int)stream.Length)]; stream.ReadExactly(bytes); return Inspect(bytes, environment);
    }
    static string Safe(string text) => text.Replace("\r", " ").Replace("\n", " ").Replace("<", "&lt;").Replace(">", "&gt;");
    public static string Markdown(Report r)
    {
        var b = new StringBuilder("# .NET configuration review\n\n" + r.Scope + "\n\nEnvironment: " + r.Environment + "\n\nInput SHA-256: `" + r.InputSha256 + "`\n");
        foreach (var f in r.Findings) b.AppendLine($"\n- **{f.Priority} / {f.Rule}** at {Safe(f.JsonPath)}: {Safe(f.Observation)} {Safe(f.Recommendation)}");
        return b.ToString();
    }
}
