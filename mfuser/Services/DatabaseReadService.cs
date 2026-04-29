using Serilog;

public static class DatabaseReadService
{
    private static readonly ILogger Logger = Log.ForContext(typeof(DatabaseReadService));

    public static async Task ReadShieldedPathsFromDbAsync(
        CancellationToken cancellationToken,
        ISet<string> shieldedPaths)
    {
        ArgumentNullException.ThrowIfNull(shieldedPaths);

        ShieldedFileSystemRepository shieldedFileSystemRepository = new();
        HashSet<string> checkedPaths = new(StringComparer.OrdinalIgnoreCase);

        var explicitlyTrackedItems = await shieldedFileSystemRepository
            .GetAllExplicitlyTrackedAsync(null, true, true, cancellationToken)
            .ConfigureAwait(false);

        foreach (var explicitlyTrackedItem in explicitlyTrackedItems)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (explicitlyTrackedItem.ItemType != ShieldedItemType.Directory)
            {
                continue;
            }

            TryAddExistingPath(
                shieldedPaths,
                checkedPaths,
                explicitlyTrackedItem.FullPath,
                Directory.Exists,
                "directory");
        }

        var allShieldedFiles = await shieldedFileSystemRepository
            .GetAll(ShieldedItemType.File)
            .ConfigureAwait(false);

        foreach (var shieldedFileItem in allShieldedFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();

            TryAddExistingPath(
                shieldedPaths,
                checkedPaths,
                shieldedFileItem.FullPath,
                File.Exists,
                "file");
        }
    }

    private static void TryAddExistingPath(
        ISet<string> shieldedPaths,
        ISet<string> checkedPaths,
        string? rawPath,
        Func<string, bool> pathExistsPredicate,
        string pathType)
    {
        ArgumentNullException.ThrowIfNull(shieldedPaths);
        ArgumentNullException.ThrowIfNull(checkedPaths);
        ArgumentNullException.ThrowIfNull(pathExistsPredicate);

        string? normalizedFullPath = rawPath?.Trim();

        if (string.IsNullOrWhiteSpace(normalizedFullPath))
        {
            return;
        }

        if (!checkedPaths.Add(normalizedFullPath))
        {
            return;
        }

        try
        {
            if (pathExistsPredicate(normalizedFullPath))
            {
                shieldedPaths.Add(normalizedFullPath);
            }
        }
        catch (Exception exceptionObject)
        {
            Logger.Warning(
                exceptionObject,
                "MINIFILTER: Skipping inaccessible {PathType} path: {FullPath}",
                pathType,
                normalizedFullPath);
        }
    }
}