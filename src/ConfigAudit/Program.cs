using System.Text.Json;
namespace ConfigAudit;
public static class Program
{
    public static int Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--help") { Console.WriteLine("ConfigAudit INPUT.json OUTPUT_DIRECTORY [Production|Development|Unknown]"); return 0; }
        if (args.Length is < 2 or > 3) return 2;
        try
        {
            var result = Auditor.Load(args[0], args.Length == 3 ? args[2] : "Unknown");
            Directory.CreateDirectory(args[1]);
            File.WriteAllText(Path.Combine(args[1], "config.json"), JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true }));
            File.WriteAllText(Path.Combine(args[1], "config.md"), Auditor.Markdown(result));
            Console.WriteLine($"Inspected leaves: {result.InspectedLeaves}; observations: {result.Findings.Count}. Setting values were not exported.");
            return 0;
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException or JsonException or ArgumentException or OverflowException)
        { Console.Error.WriteLine("Input/report error: " + e.Message); return 2; }
    }
}
