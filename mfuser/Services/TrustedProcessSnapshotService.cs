using mfuser.Models;
using Serilog;
using System.IO;

namespace mfuser.Services;

/// <summary>
/// On-disk encrypted+signed snapshot of the trusted-process list. The kernel
/// reads this file at first-volume attach (mirroring the policy snapshot) so
/// Authenticode-verified apps still get the upper half of the access-right
/// bitmask during the boot window before the agent reconnects.
///
/// Symmetric with <see cref="PolicySnapshotService"/>: same dirty-flag /
/// semaphore pattern, same atomic temp-file-then-replace write strategy, same
/// 30-second periodic flush schedule via <see cref="KernelComm"/>'s poller.
/// Payload type is TRUSTED_PROCESS_SYNC; every entry is shipped as Add since
/// the kernel-side ART is empty at boot.
/// </summary>
public static class TrustedProcessSnapshotService
{
    private static readonly ILogger Logger = Log.ForContext(typeof(TrustedProcessSnapshotService));

    private const string TrustedProcessesSnapshotFilePath =
        @"C:\Windows\minifilter_secure_folder\trusted_processes_snapshot.bin";

    public static string FilePath => TrustedProcessesSnapshotFilePath;

    private static readonly SemaphoreSlim UpdateLock = new(1, 1);

    // 0 = clean, 1 = dirty. Same coalescing pattern as PolicySnapshotService.
    private static int _isDirty;

    public static void MarkDirty()
    {
        Interlocked.Exchange(ref _isDirty, 1);
    }

    private static bool IsDirty() => Volatile.Read(ref _isDirty) == 1;

    private static void ClearDirty() => Interlocked.Exchange(ref _isDirty, 0);

    /// <summary>
    /// Re-writes trusted_processes_snapshot.bin if the in-memory dirty flag is set.
    /// Returns true iff a fresh file was successfully produced; false on
    /// "nothing to do" (not dirty / already written) or on swallow-able
    /// errors. Hard errors propagate as exceptions.
    /// </summary>
    public static async Task<bool> UpdateAsync(CancellationToken cancellationToken)
    {
        if (!IsDirty()) return false;

        await UpdateLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (!IsDirty()) return false;

            // Clear-before-write claim semantics, identical to PolicySnapshotService:
            // a concurrent MarkDirty that lands between our clear and the read
            // of TrustedProcessStore.Load surfaces correctly on the next poll
            // because we re-set on write failure and never lose the signal.
            ClearDirty();

            bool isWritten = WriteFile();

            if (!isWritten)
            {
                MarkDirty();
            }

            return isWritten;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            MarkDirty();
            throw;
        }
        catch (Exception ex)
        {
            MarkDirty();
            Logger.Error(ex, "MINIFILTER: Unexpected error while updating trusted_processes_snapshot.bin.");
            return false;
        }
        finally
        {
            UpdateLock.Release();
        }
    }

    private static bool WriteFile()
    {
        List<TrustedProcessEntry> entries = TrustedProcessStore.Load();

        var payloadEntries = new List<PayloadBuilders.TrustedProcessSyncPayloadEntry>(entries.Count);
        foreach (TrustedProcessEntry entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.ImagePath)) continue;

            string ntPathLowercase = PathTranslator.DosPathToNtPath(entry.ImagePath);
            if (string.IsNullOrWhiteSpace(ntPathLowercase))
            {
                Logger.Warning(
                    "MINIFILTER: Skipping trusted-process entry with unresolvable NT path: {Path}",
                    entry.ImagePath);
                continue;
            }

            payloadEntries.Add(new PayloadBuilders.TrustedProcessSyncPayloadEntry(
                MessageContract.PolicySyncStatus.Add,
                ntPathLowercase));
        }

        try
        {
            PayloadBuilders.PayloadBuildResult payloadResult =
                PayloadBuilders.BuildTrustedProcessSyncPayload(payloadEntries);

            byte[] finalMessageBytes = MessageBuilders.BuildMessage(
                MessageContract.PayloadType.TrustedProcessSync,
                payloadResult.Payload.Span,
                payloadResult.ItemCount,
                MessageBuilders.MessageProtection.EncryptedSigned);

            return WriteFileAtomically(TrustedProcessesSnapshotFilePath, finalMessageBytes);
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "MINIFILTER: WriteFile (trusted_processes_snapshot.bin) failed.");
            return false;
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
        catch (Exception ex)
        {
            Logger.Error(
                ex,
                "MINIFILTER: Failed to write trusted_processes_snapshot.bin atomically. Temp={TempPath}, Target={TargetPath}",
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
}
