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
    /// policy-sync message. All paths share the same <paramref name="operation"/>.
    /// For a single-path submit, just pass a one-element list.
    /// </summary>
    public void InformDriver(IReadOnlyList<string> paths, ShieldOperationType operation)
    {
        if (paths is null) throw new ArgumentNullException(nameof(paths));
        if (paths.Count == 0) return;

        (MessageContract.PolicySyncStatus status, MessageContract.AccessPolicy access) =
            MapOperation(operation);

        // Build & validate every entry up front; any per-path validation
        // failure aborts the whole call before any message is sent.
        var entries = new List<PayloadBuilders.PolicySyncPayloadEntry>(paths.Count);
        foreach (string path in paths)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                throw new ArgumentException("Path collection contains a null/empty path.", nameof(paths));
            }

            entries.Add(BuildPolicySyncPayloadEntry(status, access, path));
        }

        var payloadBuildResult = PayloadBuilders.BuildPolicySyncPayload(entries);

        byte[] inputContainer = MessageBuilders.BuildMessage(
            MessageContract.PayloadType.PolicySync,
            payloadBuildResult.Payload.Span,
            payloadBuildResult.ItemCount,
            MessageBuilders.MessageProtection.EncryptedSigned);

        _connectionService.SendMessageToKernelOrThrow(inputContainer);

        Logger.Information(
            "MINIFILTER: Policy sync sent to kernel. Operation: {Operation}, Paths: {Count}",
            operation,
            paths.Count);
    }

    private static (MessageContract.PolicySyncStatus status, MessageContract.AccessPolicy access) MapOperation(
        ShieldOperationType operation) =>
        operation switch
        {
            ShieldOperationType.Shield   => (MessageContract.PolicySyncStatus.Add, MessageContract.AccessPolicy.AllButDelete),
            ShieldOperationType.Unshield => (MessageContract.PolicySyncStatus.Remove, MessageContract.AccessPolicy.AllAccess),
            _ => throw new ArgumentOutOfRangeException(nameof(operation), operation, "Unsupported driver inform operation."),
        };

    private static PayloadBuilders.PolicySyncPayloadEntry BuildPolicySyncPayloadEntry(
        MessageContract.PolicySyncStatus policySyncStatus,
        MessageContract.AccessPolicy allowedAccessPolicy,
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

        int entryPayloadBytes = checked(
            sizeof(byte) +
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
            (uint)allowedAccessPolicy,
            ntPathLowercase);
    }
}
