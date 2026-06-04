using mfuser.Models;
using Serilog;
using System.Text;

namespace mfuser.Services;

public enum ShieldOperationType
{
    Shield = 1,
    Unshield = 2,
}

public sealed class PolicySyncService
{
    private static readonly ILogger Logger = Log.ForContext<PolicySyncService>();

    private const int MaxPolicyEntryPayloadBytes = 32 * 1024;

    private readonly ConnectionService _connectionService;

    public PolicySyncService(ConnectionService connectionService)
    {
        _connectionService = connectionService ?? throw new ArgumentNullException(nameof(connectionService));
    }

    /// <summary>
    /// Sends one or more paths to the minifilter as a single encrypted+signed
    /// policy-sync message. All paths share the same <paramref name="operation"/>
    /// and <paramref name="mode"/>.
    ///
    /// For a single-path submit, just pass a one-element list. The mode is
    /// irrelevant for Unshield (kernel ignores rights on Remove) but the
    /// caller still has to pass one; LockInPlace is a fine default.
    /// </summary>
    public void InformDriver(
        IReadOnlyList<string> paths,
        ShieldOperationType operation,
        ShieldMode mode)
    {
        if (paths is null) throw new ArgumentNullException(nameof(paths));
        if (paths.Count == 0) return;

        (MessageContract.PolicySyncStatus status,
         MessageContract.AccessPolicy untrusted,
         MessageContract.AccessPolicy trusted) = MapOperation(operation, mode);

        // Build & validate every entry up front; any per-path validation
        // failure aborts the whole call before any message is sent.
        var entries = new List<PayloadBuilders.PolicySyncPayloadEntry>(paths.Count);
        foreach (string path in paths)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Path collection contains a null/empty path.", nameof(paths));
            }

            entries.Add(BuildPolicySyncPayloadEntry(status, untrusted, trusted, path));
        }

        var payloadBuildResult = PayloadBuilders.BuildPolicySyncPayload(entries);

        byte[] inputContainer = MessageBuilders.BuildMessage(
            MessageContract.PayloadType.PolicySync,
            payloadBuildResult.Payload.Span,
            payloadBuildResult.ItemCount,
            MessageBuilders.MessageProtection.EncryptedSigned);

        _connectionService.SendMessageToKernelOrThrow(inputContainer);

        Logger.Information(
            "MINIFILTER: Policy sync sent to kernel. Operation: {Operation}, Mode: {Mode}, Paths: {Count}, UntrustedRights: 0x{Untrusted:X}, TrustedRights: 0x{Trusted:X}",
            operation,
            mode,
            paths.Count,
            (uint)untrusted,
            (uint)trusted);
    }

    /// <summary>
    /// Maps a high-level (operation, mode) to the wire-level
    /// (status, untrusted, trusted) triple.
    ///
    /// Shield: status = Add; bitmasks come from <see cref="ShieldModeBitmask"/>
    ///   based on the selected mode.
    /// Unshield: status = Remove; the kernel ignores rights on Remove
    ///   (policy_remove just deletes the entry), so we send (None, None).
    ///   The mode argument is ignored on Unshield.
    /// </summary>
    private static (MessageContract.PolicySyncStatus status,
                    MessageContract.AccessPolicy untrusted,
                    MessageContract.AccessPolicy trusted) MapOperation(
        ShieldOperationType operation,
        ShieldMode mode)
    {
        switch (operation)
        {
            case ShieldOperationType.Shield:
            {
                (MessageContract.AccessPolicy untrusted, MessageContract.AccessPolicy trusted) =
                    ShieldModeBitmask.ToBitmasks(mode);
                return (MessageContract.PolicySyncStatus.Add, untrusted, trusted);
            }

            case ShieldOperationType.Unshield:
                return (
                    MessageContract.PolicySyncStatus.Remove,
                    MessageContract.AccessPolicy.None,
                    MessageContract.AccessPolicy.None);

            default:
                throw new ArgumentOutOfRangeException(
                    nameof(operation), operation, "Unsupported driver inform operation.");
        }
    }

    private static PayloadBuilders.PolicySyncPayloadEntry BuildPolicySyncPayloadEntry(
        MessageContract.PolicySyncStatus policySyncStatus,
        MessageContract.AccessPolicy untrustedAccessPolicy,
        MessageContract.AccessPolicy trustedAccessPolicy,
        string filePath)
    {
        if (filePath.IndexOf('\0') >= 0)
        {
            throw new ArgumentException("File path contains embedded NUL.", nameof(filePath));
        }

        string ntPathLowercase = PathTranslator.DosPathToNtPath(filePath);

        if (string.IsNullOrWhiteSpace(ntPathLowercase))
        {
            throw new InvalidOperationException($"NT path translation failed: '{filePath}'");
        }

        if (ntPathLowercase.IndexOf('\0') >= 0)
        {
            throw new InvalidOperationException("Translated NT path contains embedded NUL.");
        }

        int pathUtf8ByteCount = Encoding.UTF8.GetByteCount(ntPathLowercase);

        // Entry on the wire:
        //   status(1) + access_right_untrusted(4) + access_right_trusted(4)
        //   + path_length(4) + path bytes + NUL(1)
        int entryPayloadBytes = checked(
            sizeof(byte) +
            sizeof(uint) +
            sizeof(uint) +
            sizeof(uint) +
            pathUtf8ByteCount +
            1);

        if (entryPayloadBytes > MaxPolicyEntryPayloadBytes)
        {
            throw new InvalidOperationException(
                $"Single policy entry payload exceeds {MaxPolicyEntryPayloadBytes} bytes.");
        }

        return new PayloadBuilders.PolicySyncPayloadEntry(
            policySyncStatus,
            (uint)untrustedAccessPolicy,
            (uint)trustedAccessPolicy,
            ntPathLowercase);
    }
}
