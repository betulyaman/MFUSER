using Serilog;
using System.Text;

public sealed class PolicySyncService : IDriverService
{
    private static readonly ILogger Logger = Log.ForContext<PolicySyncService>();

    private const int MaxPolicyEntryPayloadBytes = 32 * 1024;

    private readonly ConnectionService _connectionService;
    private readonly BlacklistService _blacklistService;

    public PolicySyncService(
        ConnectionService connectionService,
        BlacklistService blacklistService)
    {
        _connectionService = connectionService ?? throw new ArgumentNullException(nameof(connectionService));
        _blacklistService = blacklistService ?? throw new ArgumentNullException(nameof(blacklistService));
    }

    public void InformDriver(DriverInformOperation operation, string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Path cannot be null, empty, or whitespace.", nameof(path));
        }

        MessageContract.PolicySyncStatus policySyncStatus;
        MessageContract.AccessPolicy allowedAccessPolicy;

        switch (operation)
        {
            case DriverInformOperation.Shield:
                policySyncStatus = MessageContract.PolicySyncStatus.Add;
                allowedAccessPolicy = MessageContract.AccessPolicy.AllButDelete;

                break;

            case DriverInformOperation.Unshield:
                policySyncStatus = MessageContract.PolicySyncStatus.Remove;
                allowedAccessPolicy = MessageContract.AccessPolicy.AllAccess;

                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(operation), operation, "Unsupported driver inform operation.");
        }

        _blacklistService.MarkBlacklistDirty();

        PayloadBuilders.PolicySyncPayloadEntry payloadEntry =
            BuildPolicySyncPayloadEntry(policySyncStatus, allowedAccessPolicy, path);

        SendSinglePolicySyncEntry(payloadEntry);

        Logger.Information(
            "MINIFILTER: Policy sync sent to kernel. Operation: {Operation}, Path: {Path}",
            operation,
            path);
    }

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

    private void SendSinglePolicySyncEntry(PayloadBuilders.PolicySyncPayloadEntry payloadEntry)
    {
        var payloadEntries = new List<PayloadBuilders.PolicySyncPayloadEntry>(1)
        {
            payloadEntry
        };

        var payloadBuildResult = PayloadBuilders.BuildPolicySyncPayload(payloadEntries);

        byte[] inputContainer = MessageBuilders.BuildMessage(
            MessageContract.PayloadType.PolicySync,
            payloadBuildResult.Payload.Span,
            payloadBuildResult.ItemCount,
            MessageBuilders.MessageProtection.EncryptedSigned);

        _connectionService.SendMessageToKernelOrThrow(inputContainer);
    }
}