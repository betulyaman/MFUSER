using mfuser.Services;
using Serilog;
using System.IO;
using System.Text.Json;

namespace mfuser.Models;

/// <summary>
/// On-disk persistence for the trusted-process list. Mirrors
/// <see cref="OperationStore"/> but for image paths the agent has flagged
/// as trusted. Lives next to operations.json so the same secure folder
/// covers both.
///
/// Note: the kernel persists shielded-file policy via policy_snapshot.bin
/// and the trusted-process list via trusted_processes_snapshot.bin (both
/// written by the corresponding *SnapshotService classes). This JSON file
/// is the agent-side UI mirror.
/// </summary>
public static class TrustedProcessStore
{
    private static readonly ILogger Logger = Log.ForContext(typeof(TrustedProcessStore));

    public static string FilePath { get; set; } =
        @"C:\Windows\minifilter_secure_folder\trusted_processes.json";

    private static readonly JsonSerializerOptions SerializerOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
    };

    public static List<TrustedProcessEntry> Load()
    {
        try
        {
            if (!File.Exists(FilePath)) return new List<TrustedProcessEntry>();
            string json = File.ReadAllText(FilePath);
            return JsonSerializer.Deserialize<List<TrustedProcessEntry>>(json, SerializerOptions)
                   ?? new List<TrustedProcessEntry>();
        }
        catch (Exception ex)
        {
            Logger.Warning(ex, "TrustedProcessStore: failed to load {FilePath}; starting empty.", FilePath);
            return new List<TrustedProcessEntry>();
        }
    }

    public static void Save(IEnumerable<TrustedProcessEntry> entries)
    {
        try
        {
            string? directory = Path.GetDirectoryName(FilePath);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            string json = JsonSerializer.Serialize(entries, SerializerOptions);
            File.WriteAllText(FilePath, json);

            // Two on-disk snapshots depend on trusted_processes.json:
            //   - policy_snapshot.bin pins trusted_processes.json itself as a
            //     protected path so the kernel can lock it across restarts.
            //   - trusted_processes_snapshot.bin is the encrypted+signed
            //     mirror the kernel reads at boot to populate
            //     g_trusted_process_tree before the agent has reconnected.
            // Mark both dirty so the periodic poll (or the next manual
            // flush) catches them up.
            PolicySnapshotService.MarkDirty();
            TrustedProcessSnapshotService.MarkDirty();
        }
        catch (Exception ex)
        {
            // Persisting must never crash the app. Log and swallow.
            Logger.Warning(ex, "TrustedProcessStore: failed to save {FilePath}.", FilePath);
        }
    }
}
