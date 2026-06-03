using mfuser.Models;
using Serilog;
using System.IO;

namespace mfuser.Services;

/// <summary>
/// Agent-side writer for the encrypted+signed policy ART snapshot
/// (policy_snapshot.bin). The kernel reads this file at first-volume attach
/// so the shielded-path set is in place before the agent has had a chance to
/// reconnect after a reboot.
///
/// Symmetric with <see cref="TrustedProcessSnapshotService"/>: same dirty-
/// flag + semaphore + atomic-temp-then-replace write strategy. The wire
/// format on disk is the same as a port message, carrying a
/// PAYLOAD_TYPE_POLICY_SNAPSHOT payload.
/// </summary>
public static class PolicySnapshotService
{
    private static readonly ILogger Logger = Log.ForContext(typeof(PolicySnapshotService));

    private const string PolicySnapshotFilePath =
        @"C:\Windows\minifilter_secure_folder\policy_snapshot.bin";

    public static string FilePath => PolicySnapshotFilePath;

    private static readonly SemaphoreSlim UpdateLock = new(1, 1);

    // 0 = clean, 1 = dirty. Coalesces concurrent change signals so we write
    // the file at most once per (set of) change(s).
    private static int _isDirty;

    public static void MarkDirty()
    {
        Interlocked.Exchange(ref _isDirty, 1);
    }

    private static bool IsDirty() => Volatile.Read(ref _isDirty) == 1;

    private static void ClearDirty() => Interlocked.Exchange(ref _isDirty, 0);

    /// <summary>
    /// Rewrites policy_snapshot.bin if there are pending changes. Returns
    /// true iff a fresh file was successfully produced; false on "nothing to
    /// do" or on swallow-able errors. Hard cancellations propagate.
    /// </summary>
    public static async Task<bool> UpdateAsync(CancellationToken cancellationToken)
    {
        if (!IsDirty())
        {
            return false;
        }

        await UpdateLock.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            if (!IsDirty())
            {
                return false;
            }

            // Claim-and-clear pattern: a concurrent MarkDirty that lands
            // between our clear and the snapshot read surfaces correctly on
            // the next poll because we re-set on write failure.
            ClearDirty();

            bool isWritten = WriteSnapshotToFile(PolicySnapshotFilePath);

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
        catch (Exception exceptionObject)
        {
            MarkDirty();
            Logger.Error(exceptionObject, "MINIFILTER: Unexpected error while updating policy_snapshot.bin.");
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
                "MINIFILTER: Failed to write policy_snapshot.bin atomically. Temp={TempPath}, Target={TargetPath}",
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

    private static bool WriteSnapshotToFile(string snapshotFilePath)
    {
        if (string.IsNullOrWhiteSpace(snapshotFilePath))
        {
            throw new ArgumentException("Policy snapshot file path is null or empty.", nameof(snapshotFilePath));
        }

        HashSet<string> pathSet = new(StringComparer.OrdinalIgnoreCase)
        {
            // policy_snapshot.bin protects itself: the kernel reads this file
            // at boot, so it must remain readable and tamper-proof.
            snapshotFilePath,

            // operations.json is the authoritative shielded-path database.
            // The CONNECTION_CONTEXT payload tells the kernel about it once
            // the agent connects, but baking it into the snapshot keeps it
            // protected during the boot window before the agent initializes.
            OperationStore.FilePath,

            // trusted_processes.json is reloaded by the agent at startup and
            // replayed to the kernel; treat it with the same care.
            TrustedProcessStore.FilePath,

            // The encrypted kernel boot snapshot of the trusted-process list.
            // Read by the minifilter on first-volume attach, so it must
            // remain readable AND tamper-proof.
            TrustedProcessSnapshotService.FilePath,
        };

        JsonReadService.ReadShieldedPaths(pathSet);

        // The boot-time snapshot defaults every entry to Lock-in-place
        // softened semantics, matching the kernel-side default
        // (untrusted = ACCESS_RIGHT_ALL_BUT_DESTRUCTIVE, trusted = ACCESS_RIGHT_ALL).
        // When per-path modes become a first-class concept in the on-disk
        // policy, persist them in operations.json and feed them through here.
        const uint untrustedRights = (uint)MessageContract.AccessPolicy.AllButDestructive;
        const uint trustedRights = (uint)MessageContract.AccessPolicy.AllAccess;

        var entries = new List<PayloadBuilders.PolicySnapshotPayloadEntry>(pathSet.Count);
        foreach (string dosPath in pathSet)
        {
            entries.Add(new PayloadBuilders.PolicySnapshotPayloadEntry(
                dosPath,
                untrustedRights,
                trustedRights));
        }

        try
        {
            // 1) Build the policy-snapshot payload. Kernel routes this via
            // validate_and_store_payload_policy_snapshot into the policy ART.
            var payloadResult = PayloadBuilders.BuildPolicySnapshotPayload(entries);

            // 2) Wrap as encrypted+signed container.
            byte[] finalMessageBytes = MessageBuilders.BuildMessage(
                MessageContract.PayloadType.PolicySnapshot,
                payloadResult.Payload.Span,
                payloadResult.ItemCount,
                MessageBuilders.MessageProtection.EncryptedSigned);

            // 3) Atomic write.
            return WriteFileAtomically(snapshotFilePath, finalMessageBytes);
        }
        catch (Exception exceptionObject)
        {
            Logger.Error(exceptionObject, "MINIFILTER: WriteSnapshotToFile (policy_snapshot.bin) failed.");

            return false;
        }
    }
}
