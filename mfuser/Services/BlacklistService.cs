using Serilog;
using System.IO;

namespace mfuser.Services;

public static class BlacklistService
{
    private static readonly ILogger Logger = Log.ForContext(typeof(BlacklistService));

    private const string BlacklistFilePath = @"E:\workspace\mfuser\blacklist.txt";

    private static readonly SemaphoreSlim UpdateLock = new(1, 1);

    // Atomic dirty flag used to coalesce blacklist updates across threads.
    // 0 = clean, 1 = dirty.
    private static int _isBlacklistDirty;

    public static void MarkBlacklistDirty()
    {
        Interlocked.Exchange(ref _isBlacklistDirty, 1);
    }

    private static bool IsBlacklistDirty()
    {
        return Volatile.Read(ref _isBlacklistDirty) == 1;
    }

    private static void ClearBlacklistDirtyFlag()
    {
        Interlocked.Exchange(ref _isBlacklistDirty, 0);
    }

    // Updates the encrypted blacklist file if there are pending changes.
    public static async Task<bool> UpdateBlacklistFileAsync(CancellationToken cancellationToken)
    {
        if (!IsBlacklistDirty())
        {
            // No pending change.
            return false;
        }

        await UpdateLock.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            if (!IsBlacklistDirty())
            {
                return false;
            }

            ClearBlacklistDirtyFlag();

            bool isWritten = WriteBlacklistToFile(BlacklistFilePath);

            if (!isWritten)
            {
                MarkBlacklistDirty();
            }

            return isWritten;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Restore dirty flag so the update can be retried later.
            MarkBlacklistDirty();

            throw;
        }
        catch (Exception exceptionObject)
        {
            MarkBlacklistDirty();
            Logger.Error(exceptionObject, "MINIFILTER: Unexpected error while updating blacklist file.");

            return false;
        }
        finally
        {
            UpdateLock.Release();
        }
    }

    private static bool WriteFileAtomically(string targetFilePath, ReadOnlySpan<byte> content)
    {
        if (string.IsNullOrWhiteSpace(targetFilePath))
        {
            throw new ArgumentException("Invalid target file path.", nameof(targetFilePath));
        }

        string? targetDirectoryPath = Path.GetDirectoryName(targetFilePath);

        if (string.IsNullOrWhiteSpace(targetDirectoryPath))
        {
            throw new ArgumentException("Could not determine directory for target file.", nameof(targetFilePath));
        }

        Directory.CreateDirectory(targetDirectoryPath);

        string temporaryFilePath = Path.Combine(targetDirectoryPath, Path.GetRandomFileName());

        try
        {
            using (FileStream fileStream = new(
                       temporaryFilePath,
                       FileMode.CreateNew,
                       FileAccess.Write,
                       FileShare.None,
                       bufferSize: 4096,
                       FileOptions.WriteThrough))
            {
                if (!content.IsEmpty)
                {
                    fileStream.Write(content);
                }

                fileStream.Flush(true);
            }

            try
            {
                if (File.Exists(targetFilePath))
                {
                    File.Replace(temporaryFilePath, targetFilePath, null, ignoreMetadataErrors: true);
                }
                else
                {
                    File.Move(temporaryFilePath, targetFilePath);
                }
            }
            catch (IOException)
            {
                if (File.Exists(targetFilePath))
                {
                    File.Replace(temporaryFilePath, targetFilePath, null, ignoreMetadataErrors: true);
                }
                else
                {
                    throw;
                }
            }

            return true;
        }
        catch (Exception exceptionObject)
        {
            Logger.Error(
                exceptionObject,
                "MINIFILTER: Failed to write file atomically. Temp={TempPath}, Target={TargetPath}",
                temporaryFilePath,
                targetFilePath);

            try
            {
                if (File.Exists(temporaryFilePath))
                {
                    File.Delete(temporaryFilePath);
                }
            }
            catch
            {
                // Ignore cleanup errors.
            }

            return false;
        }
    }

    private static bool WriteBlacklistToFile(string blacklistFilePath)
    {
        if (string.IsNullOrWhiteSpace(blacklistFilePath))
        {
            throw new ArgumentException("Blacklist file path is null or empty.", nameof(blacklistFilePath));
        }

        HashSet<string> pathSet = new(StringComparer.OrdinalIgnoreCase)
        {
            blacklistFilePath // blacklist.txt must contain its own file path
        };

        JsonReadService.ReadShieldedPaths(pathSet);

        try
        {
            // 1) Build BLACKLIST payload
            var payloadResult = PayloadBuilders.BlacklistPayloadBuilder(pathSet);

            // 2) Build encrypted+signed message
            byte[] finalMessageBytes = MessageBuilders.BuildMessage(
                MessageContract.PayloadType.Blacklist,
                payloadResult.Payload.Span,
                payloadResult.ItemCount,
                MessageBuilders.MessageProtection.EncryptedSigned);

            // 3) Atomically write file
            return WriteFileAtomically(blacklistFilePath, finalMessageBytes);
        }
        catch (Exception exceptionObject)
        {
            Logger.Error(exceptionObject, "MINIFILTER: WriteBlacklistToFile failed.");

            return false;
        }
    }
}
