using Serilog;
using System.Collections.ObjectModel;
using System.Runtime.InteropServices;
using System.Threading.Channels;

/// <summary>
/// Receives, decodes, logs, and dispatches messages from the minifilter driver.
/// </summary>
public sealed class Listener : BackgroundService
{
    private static readonly ILogger Logger = Log.ForContext<Listener>();

    private readonly ConnectionService _connectionService;
    private readonly IHostApplicationLifetime _hostApplicationLifetime;
    private readonly ShieldCommunicationRpcClientFactory _shieldCommunicationRpcClientFactory;

    private static readonly TimeSpan InitialErrorDelay = TimeSpan.FromMilliseconds(250);
    private static readonly TimeSpan MaximumErrorDelay = TimeSpan.FromMilliseconds(4000);

    private static readonly ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> EmptyUnauthorizedOperations =
        Array.AsReadOnly(Array.Empty<MessageContract.UnauthorizedOperationInfo>());

    private static readonly ReadOnlyCollection<PayloadParser.ParsedLogEntry> EmptyLogEntries =
        Array.AsReadOnly(Array.Empty<PayloadParser.ParsedLogEntry>());

    private static readonly int NativeFilterMessageHeaderSize =
        Marshal.SizeOf<FilterManagerNativeMethods.NativeFilterMessageHeader>();

    private static readonly int PlaintextMessageHeaderSize =
        Marshal.SizeOf<MessageContract.PlaintextMessageHeader>();

    private static readonly int SignedMessageHeaderSize =
        Marshal.SizeOf<MessageContract.SignedMessageHeader>();

    private static readonly int EncryptedMessageHeaderSize =
        Marshal.SizeOf<MessageContract.EncryptedMessageHeader>();

    private static readonly int EncryptedContainerMaximumSize =
        checked(EncryptedMessageHeaderSize + (int)MessageContract.MaxCiphertextBytes);

    private static readonly int SignedContainerMaximumSize =
        checked(SignedMessageHeaderSize + (int)MessageContract.MaxSignedBytes);

    private static readonly int PlaintextContainerMaximumSize =
        checked(PlaintextMessageHeaderSize + (int)MessageContract.MaxPayloadBytes);

    private static readonly int MaximumContainerSize =
        Math.Max(
            EncryptedContainerMaximumSize,
            Math.Max(SignedContainerMaximumSize, PlaintextContainerMaximumSize));

    private static readonly int MaximumMessageBufferSize =
        checked(NativeFilterMessageHeaderSize + MaximumContainerSize);

    private enum GetMessageResult
    {
        Success,
        ConnectionClosed,
        InvalidMessage,
        RecoverableError
    }

    private enum MessageContainerParseFailureReason
    {
        None,
        NullBuffer,
        NativeBufferTooSmall,
        EmptyContainerCandidate,
        UnknownOuterMessageType,
        BufferTooSmallForPlaintextHeader,
        BufferTooSmallForSignedHeader,
        BufferTooSmallForEncryptedHeader,
        InvalidPlaintextHeaderSize,
        PlaintextPayloadTooLarge,
        InvalidSignedMessageLength,
        InvalidCiphertextLength,
        OuterContainerLengthOverflow,
        OuterContainerLengthOutOfRange
    }

    public Listener(
        IHostApplicationLifetime hostApplicationLifetime,
        ConnectionService connectionService,
        ShieldCommunicationRpcClientFactory shieldCommunicationRpcClientFactory)
    {
        _hostApplicationLifetime = hostApplicationLifetime ?? throw new ArgumentNullException(nameof(hostApplicationLifetime));
        _connectionService = connectionService ?? throw new ArgumentNullException(nameof(connectionService));
        _shieldCommunicationRpcClientFactory = shieldCommunicationRpcClientFactory ?? throw new ArgumentNullException(nameof(shieldCommunicationRpcClientFactory));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        Logger.Debug("MINIFILTER: Listener started.");

        IntPtr messageBuffer = IntPtr.Zero;
        TimeSpan currentErrorDelay = InitialErrorDelay;

        Channel<MessageContract.UnauthorizedOperationInfo> unauthorizedOperationChannel =
            Channel.CreateBounded<MessageContract.UnauthorizedOperationInfo>(
                new BoundedChannelOptions(1024)
                {
                    SingleReader = true,
                    SingleWriter = true,
                    FullMode = BoundedChannelFullMode.Wait
                });

        Task unauthorizedOperationWorker =
            ProcessUnauthorizedOperationsAsync(
                unauthorizedOperationChannel.Reader,
                stoppingToken);

        try
        {
            messageBuffer = Marshal.AllocHGlobal(MaximumMessageBufferSize);

            while (!stoppingToken.IsCancellationRequested)
            {
                MinifilterReadResult readResult =
                    await GetMessageFromMinifilterAsync(
                            messageBuffer,
                            stoppingToken)
                        .ConfigureAwait(false);

                switch (readResult.Result)
                {
                    case GetMessageResult.Success:
                        {
                            currentErrorDelay = InitialErrorDelay;

                            HandleLogEntries(readResult.LogEntries);

                            await EnqueueUnauthorizedOperationsAsync(
                                    readResult.UnauthorizedOperations,
                                    unauthorizedOperationChannel.Writer,
                                    stoppingToken)
                                .ConfigureAwait(false);

                            break;
                        }

                    case GetMessageResult.ConnectionClosed:
                        {
                            currentErrorDelay = InitialErrorDelay;
                            await Task.Delay(currentErrorDelay, stoppingToken).ConfigureAwait(false);

                            break;
                        }

                    case GetMessageResult.InvalidMessage:
                    case GetMessageResult.RecoverableError:
                    default:
                        {
                            await Task.Delay(currentErrorDelay, stoppingToken).ConfigureAwait(false);
                            currentErrorDelay = GetNextErrorDelay(currentErrorDelay);

                            break;
                        }
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            unauthorizedOperationChannel.Writer.TryComplete();

            try
            {
                await unauthorizedOperationWorker.ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
            }
            catch (Exception exception)
            {
                Logger.Error(exception, "MINIFILTER: Unauthorized operation worker stopped unexpectedly.");
            }

            if (messageBuffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(messageBuffer);
            }

            Logger.Debug("MINIFILTER: Listener stopped.");
        }
    }

    private async Task<MinifilterReadResult> GetMessageFromMinifilterAsync(
        IntPtr messageBuffer,
        CancellationToken cancellationToken)
    {
        try
        {
            await _connectionService.ReceiveMessageFromKernelAsync(
                    messageBuffer,
                    checked((uint)MaximumMessageBufferSize),
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (ObjectDisposedException)
        {
            Logger.Information("MINIFILTER: Receive port disposed or closed during FilterGetMessage.");

            return MinifilterReadResult.ConnectionClosed();
        }
        catch (InvalidOperationException exception)
        {
            Logger.Information(exception, "MINIFILTER: Receive port is not connected.");

            return MinifilterReadResult.ConnectionClosed();
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception exception)
        {
            Logger.Error(exception, "MINIFILTER: Exception while calling FilterGetMessage.");

            return MinifilterReadResult.RecoverableError();
        }

        try
        {
            if (!TryGetMessageContainerBytes(
                    messageBuffer,
                    out ReadOnlySpan<byte> messageBytes,
                    out MessageContainerParseFailureReason parseFailureReason))
            {
                Logger.Debug(
                    "MINIFILTER: Failed to extract a valid message container from the native receive buffer. Reason: {ParseFailureReason}",
                    parseFailureReason);

                return MinifilterReadResult.InvalidMessage();
            }

            if (!MessageDecoder.DecodeAndParseMessage(
                    messageBytes,
                    out ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> unauthorizedOperations,
                    out ReadOnlyCollection<PayloadParser.ParsedLogEntry> logEntries))
            {
                Logger.Debug("MINIFILTER: Message decode or parse failed.");

                return MinifilterReadResult.InvalidMessage();
            }

            return MinifilterReadResult.Success(unauthorizedOperations, logEntries);
        }
        catch (SEHException sehException)
        {
            Logger.Error(sehException, "MINIFILTER: Interop or marshalling error while parsing minifilter message.");

            return MinifilterReadResult.InvalidMessage();
        }
        catch (ObjectDisposedException)
        {
            Logger.Information("MINIFILTER: Receive port disposed or closed during message parse.");

            return MinifilterReadResult.ConnectionClosed();
        }
        catch (Exception exception)
        {
            Logger.Error(exception, "MINIFILTER: Unexpected exception while parsing minifilter message.");

            return MinifilterReadResult.RecoverableError();
        }
    }

    private sealed record MinifilterReadResult(
        GetMessageResult Result,
        ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> UnauthorizedOperations,
        ReadOnlyCollection<PayloadParser.ParsedLogEntry> LogEntries)
    {
        public static MinifilterReadResult Success(
            ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> unauthorizedOperations,
            ReadOnlyCollection<PayloadParser.ParsedLogEntry> logEntries) =>
            new(GetMessageResult.Success, unauthorizedOperations, logEntries);

        public static MinifilterReadResult ConnectionClosed() =>
            new(GetMessageResult.ConnectionClosed, EmptyUnauthorizedOperations, EmptyLogEntries);

        public static MinifilterReadResult InvalidMessage() =>
            new(GetMessageResult.InvalidMessage, EmptyUnauthorizedOperations, EmptyLogEntries);

        public static MinifilterReadResult RecoverableError() =>
            new(GetMessageResult.RecoverableError, EmptyUnauthorizedOperations, EmptyLogEntries);
    }

    private async Task EnqueueUnauthorizedOperationsAsync(
        ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> unauthorizedOperations,
        ChannelWriter<MessageContract.UnauthorizedOperationInfo> unauthorizedOperationWriter,
        CancellationToken stoppingToken)
    {
        if (unauthorizedOperations.Count == 0)
        {
            return;
        }

        foreach (MessageContract.UnauthorizedOperationInfo unauthorizedOperation in unauthorizedOperations)
        {
            Logger.Information(
                "MINIFILTER: UNAUTHORIZED OPERATION. OperationType: {OperationType}, FileName: {FileName}, TargetName: {TargetName}, EventTime: {EventTime}",
                unauthorizedOperation.MinifilterOperationType,
                unauthorizedOperation.FileName,
                unauthorizedOperation.TargetName,
                unauthorizedOperation.EventTime);

            if (string.IsNullOrWhiteSpace(unauthorizedOperation.FileName))
            {
                Logger.Warning("MINIFILTER: Unauthorized operation payload contains an empty FileName. Unshield request skipped.");

                continue;
            }

            await unauthorizedOperationWriter.WriteAsync(unauthorizedOperation, stoppingToken).ConfigureAwait(false);
        }
    }

    private static void HandleLogEntries(ReadOnlyCollection<PayloadParser.ParsedLogEntry> logEntries)
    {
        if (logEntries.Count == 0)
        {
            return;
        }

        foreach (PayloadParser.ParsedLogEntry logEntry in logEntries)
        {
            switch (logEntry.LogType)
            {
                case MessageContract.LogType.Info:
                    Logger.Information(
                        "MINIFILTER: Time: {Time}, Message: {Message}",
                        logEntry.Time,
                        logEntry.Message);

                    break;

                case MessageContract.LogType.Warning:
                    Logger.Warning(
                        "MINIFILTER: Time: {Time}, Message: {Message}",
                        logEntry.Time,
                        logEntry.Message);

                    break;

                case MessageContract.LogType.Failure:
                    Logger.Error(
                        "MINIFILTER: Time: {Time}, Message: {Message}",
                        logEntry.Time,
                        logEntry.Message);

                    break;

                default:
                    Logger.Debug(
                        "MINIFILTER: Time: {Time}, Message: {Message}",
                        logEntry.Time,
                        logEntry.Message);

                    break;
            }
        }
    }

    private async Task ProcessUnauthorizedOperationsAsync(
        ChannelReader<MessageContract.UnauthorizedOperationInfo> unauthorizedOperationReader,
        CancellationToken stoppingToken)
    {
        var agentServiceClient =
            _shieldCommunicationRpcClientFactory.CreateClient(ProcessName.AgentService);

        while (await unauthorizedOperationReader.WaitToReadAsync(stoppingToken).ConfigureAwait(false))
        {
            while (unauthorizedOperationReader.TryRead(out MessageContract.UnauthorizedOperationInfo unauthorizedOperation))
            {
                ShieldRequest shieldRequest = new()
                {
                    Path = unauthorizedOperation.FileName,
                    ActionType = ShieldRequest.Types.ShieldActionType.Unshield
                };

                try
                {
                    ShieldResponse shieldResponse =
                        await agentServiceClient.ShieldByActionTypeAsync(
                                shieldRequest,
                                cancellationToken: stoppingToken)
                            .ConfigureAwait(false);

                    Logger.Debug(
                        "MINIFILTER: ShieldByActionTypeAsync completed. Path: {Path}, Success: {Success}",
                        unauthorizedOperation.FileName,
                        shieldResponse.Success);
                }
                catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception exception)
                {
                    Logger.Error(
                        exception,
                        "MINIFILTER: ShieldByActionTypeAsync failed for path: {Path}",
                        unauthorizedOperation.FileName);
                }
            }
        }
    }

    private static TimeSpan GetNextErrorDelay(TimeSpan currentErrorDelay)
    {
        double nextDelayMilliseconds = currentErrorDelay.TotalMilliseconds * 2;

        if (nextDelayMilliseconds > MaximumErrorDelay.TotalMilliseconds)
        {
            nextDelayMilliseconds = MaximumErrorDelay.TotalMilliseconds;
        }

        return TimeSpan.FromMilliseconds(nextDelayMilliseconds);
    }

    private unsafe bool TryGetMessageContainerBytes(
        IntPtr messageBuffer,
        out ReadOnlySpan<byte> messageBytes,
        out MessageContainerParseFailureReason parseFailureReason)
    {
        messageBytes = default;
        parseFailureReason = MessageContainerParseFailureReason.None;

        if (messageBuffer == IntPtr.Zero)
        {
            parseFailureReason = MessageContainerParseFailureReason.NullBuffer;

            return false;
        }

        ReadOnlySpan<byte> nativeBufferBytes =
            new((void*)messageBuffer, MaximumMessageBufferSize);

        if (nativeBufferBytes.Length <= NativeFilterMessageHeaderSize)
        {
            parseFailureReason = MessageContainerParseFailureReason.NativeBufferTooSmall;

            return false;
        }

        ReadOnlySpan<byte> candidateContainerBytes =
            nativeBufferBytes.Slice(NativeFilterMessageHeaderSize);

        if (candidateContainerBytes.IsEmpty)
        {
            parseFailureReason = MessageContainerParseFailureReason.EmptyContainerCandidate;

            return false;
        }

        if (!TryGetOuterContainerLength(
                candidateContainerBytes,
                out int outerContainerLength,
                out parseFailureReason))
        {
            return false;
        }

        if (outerContainerLength <= 0 || outerContainerLength > candidateContainerBytes.Length)
        {
            parseFailureReason = MessageContainerParseFailureReason.OuterContainerLengthOutOfRange;

            return false;
        }

        messageBytes = candidateContainerBytes.Slice(0, outerContainerLength);

        return true;
    }

    private static bool TryGetOuterContainerLength(
        ReadOnlySpan<byte> candidateContainerBytes,
        out int outerContainerLength,
        out MessageContainerParseFailureReason parseFailureReason)
    {
        outerContainerLength = 0;
        parseFailureReason = MessageContainerParseFailureReason.None;

        if (candidateContainerBytes.IsEmpty)
        {
            parseFailureReason = MessageContainerParseFailureReason.EmptyContainerCandidate;

            return false;
        }

        MessageContract.MessageType outerMessageType =
            (MessageContract.MessageType)candidateContainerBytes[0];

        try
        {
            switch (outerMessageType)
            {
                case MessageContract.MessageType.Plaintext:
                    {
                        if (candidateContainerBytes.Length < PlaintextMessageHeaderSize)
                        {
                            parseFailureReason = MessageContainerParseFailureReason.BufferTooSmallForPlaintextHeader;

                            return false;
                        }

                        MessageContract.PlaintextMessageHeader plaintextMessageHeader =
                            MemoryMarshal.Read<MessageContract.PlaintextMessageHeader>(
                                candidateContainerBytes.Slice(0, PlaintextMessageHeaderSize));

                        if (plaintextMessageHeader.HeaderSize != PlaintextMessageHeaderSize)
                        {
                            parseFailureReason = MessageContainerParseFailureReason.InvalidPlaintextHeaderSize;

                            return false;
                        }

                        if (plaintextMessageHeader.PayloadLengthBytes > MessageContract.MaxPayloadBytes)
                        {
                            parseFailureReason = MessageContainerParseFailureReason.PlaintextPayloadTooLarge;

                            return false;
                        }

                        outerContainerLength = checked(
                            plaintextMessageHeader.HeaderSize + (int)plaintextMessageHeader.PayloadLengthBytes);

                        if (outerContainerLength < PlaintextMessageHeaderSize)
                        {
                            parseFailureReason = MessageContainerParseFailureReason.OuterContainerLengthOutOfRange;

                            return false;
                        }

                        return true;
                    }

                case MessageContract.MessageType.Signed:
                    {
                        if (candidateContainerBytes.Length < SignedMessageHeaderSize)
                        {
                            parseFailureReason = MessageContainerParseFailureReason.BufferTooSmallForSignedHeader;

                            return false;
                        }

                        MessageContract.SignedMessageHeader signedMessageHeader =
                            MemoryMarshal.Read<MessageContract.SignedMessageHeader>(
                                candidateContainerBytes.Slice(0, SignedMessageHeaderSize));

                        if (signedMessageHeader.SignedMessageSize == 0 ||
                            signedMessageHeader.SignedMessageSize > MessageContract.MaxSignedBytes)
                        {
                            parseFailureReason = MessageContainerParseFailureReason.InvalidSignedMessageLength;

                            return false;
                        }

                        outerContainerLength = checked(
                            SignedMessageHeaderSize + (int)signedMessageHeader.SignedMessageSize);

                        if (outerContainerLength < SignedMessageHeaderSize)
                        {
                            parseFailureReason = MessageContainerParseFailureReason.OuterContainerLengthOutOfRange;

                            return false;
                        }

                        return true;
                    }

                case MessageContract.MessageType.Encrypted:
                case MessageContract.MessageType.SignedEncrypted:
                    {
                        if (candidateContainerBytes.Length < EncryptedMessageHeaderSize)
                        {
                            parseFailureReason = MessageContainerParseFailureReason.BufferTooSmallForEncryptedHeader;

                            return false;
                        }

                        MessageContract.EncryptedMessageHeader encryptedMessageHeader =
                            MemoryMarshal.Read<MessageContract.EncryptedMessageHeader>(
                                candidateContainerBytes.Slice(0, EncryptedMessageHeaderSize));

                        if (encryptedMessageHeader.CiphertextSize == 0 ||
                            encryptedMessageHeader.CiphertextSize > MessageContract.MaxCiphertextBytes)
                        {
                            parseFailureReason = MessageContainerParseFailureReason.InvalidCiphertextLength;

                            return false;
                        }

                        outerContainerLength = checked(
                            EncryptedMessageHeaderSize + (int)encryptedMessageHeader.CiphertextSize);

                        if (outerContainerLength < EncryptedMessageHeaderSize)
                        {
                            parseFailureReason = MessageContainerParseFailureReason.OuterContainerLengthOutOfRange;

                            return false;
                        }

                        return true;
                    }

                default:
                    {
                        parseFailureReason = MessageContainerParseFailureReason.UnknownOuterMessageType;

                        return false;
                    }
            }
        }
        catch (OverflowException)
        {
            parseFailureReason = MessageContainerParseFailureReason.OuterContainerLengthOverflow;

            return false;
        }
    }
}