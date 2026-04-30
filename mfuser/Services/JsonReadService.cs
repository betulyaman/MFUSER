using mfuser.Models;
using Serilog;
using System.IO;

namespace mfuser.Services;

/// <summary>
/// Reads the set of currently-shielded paths from the operations JSON file.
///
/// A path is "currently shielded" when its most recent entry has
/// Operation == "shield" and Status == "Sent". Last-entry-wins handles
/// toggles correctly (e.g. shield -> unshield -> shield ends up shielded).
/// </summary>
public static class JsonReadService
{
    private static readonly ILogger Logger = Log.ForContext(typeof(JsonReadService));

    public static void ReadShieldedPaths(ISet<string> shieldedPaths)
    {
        ArgumentNullException.ThrowIfNull(shieldedPaths);

        foreach (var path in GetCurrentlyShieldedPaths())
        {
            TryAddExistingPath(shieldedPaths, path);
        }
    }

    // Reduce the entries in the JSON file to one path per Path (last-wins),
    // then yield only the paths that are currently shielded.
    private static IEnumerable<string> GetCurrentlyShieldedPaths()
    {
        var latestPerPath = new Dictionary<string, OperationEntry>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var entry in OperationStore.Load())
        {
            var path = entry?.Path?.Trim();
            if (string.IsNullOrWhiteSpace(path)) continue;

            latestPerPath[path] = entry;
        }

        return latestPerPath
            .Where(kv => IsCurrentlyShielded(kv.Value))
            .Select(kv => kv.Key);
    }

    private static bool IsCurrentlyShielded(OperationEntry entry) =>
        string.Equals(entry.Operation, "shield", StringComparison.OrdinalIgnoreCase)
        && string.Equals(entry.Status, "Sent", StringComparison.OrdinalIgnoreCase);

    private static void TryAddExistingPath(ISet<string> shieldedPaths, string fullPath)
    {
        try
        {
            if (File.Exists(fullPath))
            {
                shieldedPaths.Add(fullPath);
                return;
            }

            if (Directory.Exists(fullPath))
            {
                // Folder submissions expand to: the folder itself + every file
                // under it. Same expansion KernelComm.SendOperation uses, so
                // the kernel sees a consistent view at startup vs at submit.
                int added = 0;
                foreach (string expandedPath in PathExpander.ExpandToShieldPaths(fullPath))
                {
                    if (shieldedPaths.Add(expandedPath)) added++;
                }
                Logger.Debug(
                    "MINIFILTER: Expanded shielded folder {Folder} to {Count} path(s) (folder + files).",
                    fullPath,
                    added);
                return;
            }

            Logger.Information(
                "MINIFILTER: Skipping non-existent shielded path: {FullPath}",
                fullPath);
        }
        catch (Exception ex)
        {
            Logger.Warning(
                ex,
                "MINIFILTER: Skipping inaccessible shielded path: {FullPath}",
                fullPath);
        }
    }
}