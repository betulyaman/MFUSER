using mfuser.Models;
using Serilog;
using System.Text;

namespace mfuser.Services;

public enum TrustedProcessOperation
{
    Add = 1,
    Remove = 2,
}

/// <summary>
/// Manages the user-mode trusted-process list and ships TRUSTED_PROCESS_SYNC
/// messages to the kernel.
///
/// Lifecycle expectations:
///   - The kernel's trusted-process set is empty at every boot. The agent
///     replays the entire on-disk list once both communication ports are up
///     via <see cref="ReplayAllAsync"/>.
///   - Subsequent <see cref="AddAsync"/> / <see cref="RemoveAsync"/> calls
///     ship a single encrypted+signed delta and update the on-disk list.
///
/// Concurrency:
///   - Send and persistence are serialized by an internal SemaphoreSlim so
///     two concurrent UI clicks can't interleave a partial write/replay.
/// </summary>
public sealed class TrustedProcessService
{
    private static readonly ILogger Logger = Log.ForContext<TrustedProcessService>();

    private readonly ConnectionService _connectionService;
    private readonly SemaphoreSlim _stateLock = new(initialCount: 1, maxCount: 1);

    public TrustedProcessService(ConnectionService connectionService)
    {
        _connectionService = connectionService ?? throw new ArgumentNullException(nameof(connectionService));
    }

    /// <summary>
    /// Sends one add/remove for a single image path. Returns true if the
    /// kernel acknowledged the message.
    /// </summary>
    public async Task<bool> SendAsync(string imagePath, TrustedProcessOperation operation, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            throw new ArgumentException("Image path cannot be null or empty.", nameof(imagePath));
        }

        await _stateLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            return SendUnderLock(new[] { imagePath }, MapStatus(operation));
        }
        finally
        {
            _stateLock.Release();
        }
    }

    /// <summary>
    /// Pushes every entry in <see cref="TrustedProcessStore"/> to the kernel
    /// as a single Add batch. Used on startup, after the agent has connected
    /// to both ports, to repopulate the kernel-side ART from disk.
    /// </summary>
    public async Task ReplayAllAsync(CancellationToken cancellationToken)
    {
        await _stateLock.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            List<TrustedProcessEntry> entries = TrustedProcessStore.Load();
            string[] paths = entries
                .Select(e => e.ImagePath)
                .Where(p => !string.IsNullOrWhiteSpace(p))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();

            if (paths.Length == 0)
            {
                Logger.Information("MINIFILTER: TrustedProcessService.ReplayAllAsync: nothing to replay.");
                return;
            }

            bool ok = SendUnderLock(paths, MessageContract.PolicySyncStatus.Add);
            Logger.Information(
                "MINIFILTER: TrustedProcessService.ReplayAllAsync: replayed {Count} entries. Success: {Ok}",
                paths.Length,
                ok);
        }
        finally
        {
            _stateLock.Release();
        }
    }

    /// <summary>
    /// Common send path. Builds one POLICY_STATUS_ADD or _REMOVE batch from
    /// the supplied DOS paths and pushes the encrypted+signed container to
    /// the kernel.
    /// </summary>
    private bool SendUnderLock(IReadOnlyList<string> imagePaths, MessageContract.PolicySyncStatus status)
    {
        var entries = new List<PayloadBuilders.TrustedProcessSyncPayloadEntry>(imagePaths.Count);

        foreach (string imagePath in imagePaths)
        {
            if (imagePath.IndexOf('\0') >= 0)
            {
                throw new ArgumentException("Trusted-process image path contains embedded NUL.", nameof(imagePaths));
            }

            string ntPathLowercase = PathTranslator.DosPathToNtPath(imagePath);
            if (string.IsNullOrWhiteSpace(ntPathLowercase))
            {
                throw new InvalidOperationException(
                    $"Trusted-process NT path translation failed: '{imagePath}'.");
            }

            if (ntPathLowercase.IndexOf('\0') >= 0)
            {
                throw new InvalidOperationException("Translated trusted-process NT path contains embedded NUL.");
            }

            // Length sanity for the per-entry budget. UINT32 path length +
            // UINT8 status + path bytes + NUL.
            int pathUtf8ByteCount = Encoding.UTF8.GetByteCount(ntPathLowercase);
            int entryPayloadBytes = checked(sizeof(byte) + sizeof(uint) + pathUtf8ByteCount + 1);
            if (entryPayloadBytes > (int)MessageContract.MaxPayloadBytes)
            {
                throw new InvalidOperationException(
                    $"Single trusted-process entry exceeds MaxPayloadBytes ({MessageContract.MaxPayloadBytes}).");
            }

            entries.Add(new PayloadBuilders.TrustedProcessSyncPayloadEntry(status, ntPathLowercase));
        }

        PayloadBuilders.PayloadBuildResult payloadResult =
            PayloadBuilders.BuildTrustedProcessSyncPayload(entries);

        byte[] container = MessageBuilders.BuildMessage(
            MessageContract.PayloadType.TrustedProcessSync,
            payloadResult.Payload.Span,
            payloadResult.ItemCount,
            MessageBuilders.MessageProtection.EncryptedSigned);

        try
        {
            _connectionService.SendMessageToKernelOrThrow(container);
            Logger.Information(
                "MINIFILTER: Trusted-process sync sent to kernel. Status: {Status}, Paths: {Count}",
                status,
                imagePaths.Count);
            return true;
        }
        catch (Exception ex)
        {
            Logger.Error(
                ex,
                "MINIFILTER: Trusted-process sync send failed. Status: {Status}, Paths: {Count}",
                status,
                imagePaths.Count);
            return false;
        }
    }

    private static MessageContract.PolicySyncStatus MapStatus(TrustedProcessOperation operation) =>
        operation switch
        {
            TrustedProcessOperation.Add    => MessageContract.PolicySyncStatus.Add,
            TrustedProcessOperation.Remove => MessageContract.PolicySyncStatus.Remove,
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "Unsupported trusted-process operation."),
        };
}
