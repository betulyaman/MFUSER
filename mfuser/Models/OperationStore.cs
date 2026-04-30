using Serilog;
using System.IO;
using System.Text.Json;

namespace mfuser.Models;

/// <summary>
/// Loads and saves the list of submitted operations as JSON so it survives
/// application restarts.
/// </summary>
public static class OperationStore
{
    private static readonly ILogger Logger = Log.ForContext(typeof(OperationStore));

    public static string FilePath { get; set; } = @"E:\workspace\mfuser\operations.json";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    public static List<OperationEntry> Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new List<OperationEntry>();
            string json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<List<OperationEntry>>(json, SerializerOptions)
                   ?? new List<OperationEntry>();
        }
        catch (Exception ex)
        {
            // If the file is corrupt, just start empty rather than crash on launch.
            Logger.Warning(ex, "OperationStore: failed to load {FilePath}; starting with an empty list.", FilePath);
            return new List<OperationEntry>();
        }
    }

    public static void Save(IEnumerable<OperationEntry> operations)
    {
        try
        {
            string? directory = Path.GetDirectoryName(FilePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            string json = JsonSerializer.Serialize(operations, SerializerOptions);
            File.WriteAllText(FilePath, json);
        }
        catch (Exception ex)
        {
            // Saving must never crash the app on close. Log and swallow.
            Logger.Warning(ex, "OperationStore: failed to save {FilePath}.", FilePath);
        }
    }
}
