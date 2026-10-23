using ConfigAudit;
using System.Text;
using System.Text.Json;
int passed = 0, failed = 0;
void Check(bool x) { if (!x) throw new Exception("assertion failed"); }
Report Inspect(string json, string env = "Production") => Auditor.Inspect(Encoding.UTF8.GetBytes(json), env);
void Test(string name, Action test) { try { test(); passed++; Console.WriteLine("PASS " + name); } catch (Exception e) { failed++; Console.WriteLine("FAIL " + name + ": " + e.Message); } }
void Reject(string json) { try { Inspect(json); throw new Exception("accepted malformed/ambiguous data"); } catch (Exception e) when (e is InvalidDataException or JsonException) { } }
Test("safe settings produce no observations", () => Check(Inspect("{\"AllowedHosts\":\"app.example\",\"DetailedErrors\":false}").Findings.Count == 0));
Test("inline value never leaks into report", () => { var r = Inspect("{\"Password\":\"SYNTHETIC_DO_NOT_EXPORT\"}"); Check(r.Findings.Any()); Check(!JsonSerializer.Serialize(r).Contains("SYNTHETIC_DO_NOT_EXPORT")); Check(!Auditor.Markdown(r).Contains("SYNTHETIC_DO_NOT_EXPORT")); });
Test("environment reference excluded", () => Check(Inspect("{\"ApiKey\":\"${API_KEY}\"}").Findings.Count == 0));
Test("env provider reference excluded", () => Check(Inspect("{\"Token\":\"env:API_TOKEN\"}").Findings.Count == 0));
Test("percent placeholder excluded", () => Check(Inspect("{\"Secret\":\"%LOCAL_SECRET%\"}").Findings.Count == 0));
Test("nested connection string marked", () => Check(Inspect("{\"ConnectionStrings\":{\"Primary\":\"synthetic-example-only\"}}").Findings.Single().Rule == "INLINE_SENSITIVE_SETTING"));
Test("empty sensitive setting not treated as a credential", () => Check(Inspect("{\"Password\":\"\"}").Findings.Count == 0));
Test("production diagnostic priority", () => Check(Inspect("{\"DetailedErrors\":true}").Findings.Single().Priority == "medium"));
Test("development context retained", () => Check(Inspect("{\"DetailedErrors\":true}", "Development").Findings.Single().Priority == "info"));
Test("HTTP listener remains a review item", () => Check(Inspect("{\"Kestrel\":{\"Endpoints\":{\"Internal\":{\"Url\":\"http://127.0.0.1:5000\"}}}}").Findings.Single().Priority == "review"));
Test("verbose logging rule", () => Check(Inspect("{\"Logging\":{\"LogLevel\":{\"Default\":\"Debug\"}}}").Findings.Single().Rule == "VERBOSE_LOGGING"));
Test("arrays traversed without exposing values", () => Check(Inspect("{\"Services\":[{\"AccessToken\":\"synthetic\"}]}").Findings.Single().JsonPath == "$.Services[0].AccessToken"));
Test("duplicate keys rejected", () => Reject("{\"A\":1,\"A\":2}"));
Test("case ambiguous keys rejected", () => Reject("{\"A\":1,\"a\":2}"));
Test("comments and trailing commas supported", () => Check(Inspect("{/*comment*/\"Example\":1,}").InspectedLeaves == 1));
Test("root array rejected", () => Reject("[]"));
Test("invalid environment rejected", () => { try { Inspect("{}", "Maybe"); throw new Exception("accepted"); } catch (ArgumentException) { } });
Test("hash is deterministic", () => Check(Inspect("{}").InputSha256 == Inspect("{}").InputSha256));
Console.WriteLine($"{passed}/{passed + failed} passed"); return failed == 0 ? 0 : 1;
