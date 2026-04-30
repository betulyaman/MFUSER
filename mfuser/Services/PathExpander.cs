using System.IO;

namespace mfuser.Services;

/// <summary>
/// Expands a user-submitted path into the path set that needs to be
/// shielded/unshielded at the minifilter. The kernel matches per-path, so:
///   - a file submission yields just that file,
///   - a folder submission yields the folder itself <b>and</b> every file
///     underneath it (recursive).
/// The same expansion is used at submit time (KernelComm.SendOperation) and
/// when reading <c>operations.json</c> for the connection-context payload and
/// <c>blacklist.txt</c>, so the kernel always sees the same set of paths.
/// </summary>
public static class PathExpander
{
    /// <summary>
    /// Returns every path to send to the kernel for <paramref name="path"/>.
    /// File → just the file. Directory → directory itself plus all files
    /// under it. Anything that doesn't exist is silently skipped.
    /// Symlinks/junctions and inaccessible files are skipped to avoid loops
    /// and crashes mid-enumeration.
    /// </summary>
    public static IEnumerable<string> ExpandToShieldPaths(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return Array.Empty<string>();

        try
        {
            if (File.Exists(path))
            {
                return new[] { path };
            }

            if (!Directory.Exists(path))
            {
                return Array.Empty<string>();
            }

            var options = new EnumerationOptions
            {
                RecurseSubdirectories = true,
                AttributesToSkip = FileAttributes.ReparsePoint,
                IgnoreInaccessible = true,
                ReturnSpecialDirectories = false,
            };

            // Folder path first, then its files.
            return EnumerateFolderAndFiles(path, options);
        }
        catch
        {
            return Array.Empty<string>();
        }
    }

    private static IEnumerable<string> EnumerateFolderAndFiles(string folder, EnumerationOptions options)
    {
        yield return folder;

        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(folder, "*", options);
        }
        catch
        {
            yield break;
        }

        foreach (string file in files)
        {
            yield return file;
        }
    }

    /// <summary>True if <paramref name="path"/> exists and is a directory.</summary>
    public static bool IsDirectory(string? path)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        try { return Directory.Exists(path); }
        catch { return false; }
    }
}
