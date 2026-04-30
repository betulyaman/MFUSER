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

    /// <summary>
    /// Returns the most-specific currently-shielded path that contains
    /// <paramref name="filePath"/> (the file itself, or any ancestor folder).
    /// Returns <c>null</c> if no ancestor (or the file itself) is shielded.
    /// </summary>
    /// <remarks>
    /// Used by the UI to coalesce many unauthorized-op prompts (one per file
    /// under a shielded folder, plus one for the folder itself) into a single
    /// prompt for the folder. Comparison is case-insensitive and ignores any
    /// trailing directory separator on either side, so it doesn't matter
    /// whether the user typed "C:\Important" or "C:\Important\", or whether
    /// the kernel reports "C:\important\file.txt" or "\\?\C:\important\".
    /// </remarks>
    public static string? FindShieldedAncestor(string? filePath)
    {
        if (string.IsNullOrWhiteSpace(filePath)) return null;

        string fileNormalized = TrimTrailingSeparator(filePath);

        string? bestMatch = null;
        int bestLength = -1;

        foreach (string shieldedPath in GetCurrentlyShieldedPaths())
        {
            string shieldedNormalized = TrimTrailingSeparator(shieldedPath);
            if (shieldedNormalized.Length == 0) continue;

            bool isExactMatch = string.Equals(
                fileNormalized,
                shieldedNormalized,
                StringComparison.OrdinalIgnoreCase);

            bool isUnder =
                fileNormalized.Length > shieldedNormalized.Length
                && fileNormalized.StartsWith(shieldedNormalized, StringComparison.OrdinalIgnoreCase)
                && IsDirectorySeparator(fileNormalized[shieldedNormalized.Length]);

            if ((isExactMatch || isUnder) && shieldedNormalized.Length > bestLength)
            {
                bestMatch = shieldedPath; // return the user-submitted form
                bestLength = shieldedNormalized.Length;
            }
        }

        return bestMatch;
    }

    private static string TrimTrailingSeparator(string path)
    {
        // Keep drive roots ("C:\", "D:\") intact; trim only trailing separators
        // on longer paths.
        if (path.Length <= 3) return path;

        int end = path.Length;
        while (end > 0 && IsDirectorySeparator(path[end - 1]))
        {
            end--;
        }
        return end == path.Length ? path : path[..end];
    }

    private static bool IsDirectorySeparator(char c) =>
        c == Path.DirectorySeparatorChar || c == Path.AltDirectorySeparatorChar;

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