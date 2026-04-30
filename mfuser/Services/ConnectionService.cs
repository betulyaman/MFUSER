using Serilog;
using System.ComponentModel;
using System.Runtime.InteropServices;

using MinifilterPortHandle = Microsoft.Win32.SafeHandles.SafeFileHandle;

namespace mfuser.Services;

/// <summary>
/// Manages connection and authentication to the minifilter communication ports.
/// Owns the underlying port handles and is responsible for their disposal.
/// </summary>
public sealed class ConnectionService : IDisposable
{
    private static readonly ILogger Logger = Log.ForContext<ConnectionService>();

    // Serializes connect and dispose operations.
    private readonly SemaphoreSlim _connectionLock = new(initialCount: 1, maxCount: 1);

    // Lifecycle state:
    // 0 = running
    // 1 = disposing
    // 2 = disposed
    private int _lifecycleState;

    // Number of active native send/receive operations.
    // Dispose waits for this count to drop to zero before closing handles.
    private int _activeOperations;

    private readonly ManualResetEventSlim _noActiveOperationsEvent = new(initialState: true);

    // Port names should match the minifilter's actual port object names.
    private const string CommunicationPortSendMessageToKernel = "\\CommunicationPortUserToKernel";
    private const string CommunicationPortReceiveMessageFromKernel = "\\CommunicationPortKernelToUser";

    public static string DatabasePath { get; set; } = @"E:\workspace\mfuser\operations.json";

    private MinifilterPortHandle? _sendToKernelPortHandle;
    private MinifilterPortHandle? _receiveFromKernelPortHandle;

    private const int ErrorIoPending = 997;
    private const int ErrorIOIncomplete = 996;

    // 0 = no pending receive, 1 = pending receive exists
    private int _receivePending;

    // Pending receive state
    private IntPtr _pendingReceiveBuffer;
    private IntPtr _pendingReceiveOverlapped;
    private EventWaitHandle? _receiveEventHandle;

    private const int MaxReceivedMessageBufferSize = 4096;

    private enum PortKind : byte
    {
        SendToKernel,
        ReceiveFromKernel,
    }

    public enum MinifilterConnectionResult : byte
    {
        NotConnected,
        AlreadyConnected,
        ConnectedAndAuthenticated,
    }

    /// <summary>
    /// Connects the user-mode send port to the kernel communication port.
    /// Returns MinifilterConnectionResult.AlreadyConnected if the port is already connected.
    /// </summary>
    public Task<MinifilterConnectionResult> ConnectSendMessagePortToKernelAsync(CancellationToken cancellationToken)
    {
        return ConnectPortAsync(PortKind.SendToKernel, cancellationToken);
    }

    /// <summary>
    /// Connects the user-mode receive port from the kernel communication port.
    /// Returns MinifilterConnectionResult.AlreadyConnected if the port is already connected.
    /// </summary>
    public Task<MinifilterConnectionResult> ConnectReceiveMessagePortFromKernelAsync(CancellationToken cancellationToken)
    {
        return ConnectPortAsync(PortKind.ReceiveFromKernel, cancellationToken);
    }

    /// <summary>
    /// Sends a message to the kernel through the connected send port.
    /// </summary>
    public void SendMessageToKernelOrThrow(ReadOnlySpan<byte> inputBuffer)
    {
        ThrowIfDisposed();

        EnterOperation();

        try
        {
            MinifilterPortHandle? sendPortHandle = _sendToKernelPortHandle;

            if (sendPortHandle is null || sendPortHandle.IsInvalid)
            {
                throw new InvalidOperationException("Minifilter SEND->kernel communication port is not connected.");
            }

            unsafe
            {
                fixed (byte* inputPointer = inputBuffer)
                {
                    long hResult = FilterManagerNativeMethods.filter_send_message(
                        sendPortHandle,
                        (IntPtr)inputPointer,
                        checked((uint)inputBuffer.Length),
                        IntPtr.Zero,
                        0);

                    if (hResult != 0)
                    {
                        throw new InvalidOperationException(
                            $"Failed to send message to kernel. HRESULT=0x{hResult:X8}");
                    }
                }
            }
        }
        finally
        {
            ExitOperation();
        }
    }

    public async Task ReceiveMessageFromKernelAsync(IntPtr messageBuffer, uint messageBufferSize, CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (ReceiveMessageFromKernel(messageBuffer, messageBufferSize) == 1)
            {
                return;
            }

            EventWaitHandle receiveEventHandle = GetPendingReceiveEventHandle();

            await WaitHandleAsync(receiveEventHandle, cancellationToken).ConfigureAwait(false);
        }
    }

    private EventWaitHandle GetPendingReceiveEventHandle()
    {
        EventWaitHandle? receiveEventHandle = _receiveEventHandle;

        if (Volatile.Read(ref _receivePending) == 0 || receiveEventHandle is null)
        {
            throw new InvalidOperationException(
                "Receive did not complete and no pending receive event is available.");
        }

        return receiveEventHandle;
    }

    private static async Task WaitHandleAsync(
        WaitHandle waitHandle,
        CancellationToken cancellationToken)
    {
        if (waitHandle is null)
        {
            throw new ArgumentNullException(nameof(waitHandle));
        }

        if (cancellationToken.IsCancellationRequested)
        {
            throw new OperationCanceledException(cancellationToken);
        }

        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        RegisteredWaitHandle? registeredWaitHandle = null;
        CancellationTokenRegistration cancellationRegistration = default;

        try
        {
            registeredWaitHandle = ThreadPool.RegisterWaitForSingleObject(
                waitHandle,
                static (state, _) =>
                {
                    var completionSource = (TaskCompletionSource)state!;
                    completionSource.TrySetResult();
                },
                tcs,
                Timeout.Infinite,
                executeOnlyOnce: true);

            cancellationRegistration = cancellationToken.Register(
                static state =>
                {
                    var stateTuple = ((TaskCompletionSource completionSource, CancellationToken token))state!;
                    stateTuple.completionSource.TrySetCanceled(stateTuple.token);
                },
                (tcs, cancellationToken));

            await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            cancellationRegistration.Dispose();
            registeredWaitHandle?.Unregister(null);
        }
    }

    /// <summary>
    /// Receives a message from the kernel through the connected receive port.
    /// </summary>
    private unsafe int ReceiveMessageFromKernel(IntPtr messageBuffer, uint messageBufferSize)
    {
        if (messageBuffer == IntPtr.Zero)
        {
            throw new ArgumentException("Message buffer pointer cannot be zero.", nameof(messageBuffer));
        }

        if (messageBufferSize == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(messageBufferSize), "Message buffer size must be greater than zero.");
        }

        ThrowIfDisposed();

        EnterOperation();

        try
        {
            MinifilterPortHandle? receivePortHandle = _receiveFromKernelPortHandle;

            if (receivePortHandle is null || receivePortHandle.IsInvalid)
            {
                throw new InvalidOperationException("Minifilter RECEIVE<-kernel communication port is not connected.");
            }

            int readSuccess = 0;

            if (Volatile.Read(ref _receivePending) != 0)
            {
                if (_pendingReceiveBuffer == IntPtr.Zero || _pendingReceiveOverlapped == IntPtr.Zero)
                {
                    ClearPendingReceiveState();

                    throw new InvalidOperationException("Pending receive state is corrupted.");
                }

                uint transferred;
                bool completed = FilterManagerNativeMethods.GetOverlappedResult(
                    receivePortHandle,
                    _pendingReceiveOverlapped,
                    out transferred,
                    false);

                if (!completed)
                {
                    int error = Marshal.GetLastWin32Error();

                    if (error != ErrorIOIncomplete)
                    {
                        ClearPendingReceiveState();

                        throw new Win32Exception(error, "GetOverlappedResult failed.");
                    }

                    return 0;
                }

                if (transferred == 0)
                {
                    ClearPendingReceiveState();

                    return 0;
                }

                if (transferred > messageBufferSize)
                {
                    ClearPendingReceiveState();

                    throw new InvalidOperationException(
                        $"Received message size ({transferred}) exceeds caller buffer size ({messageBufferSize}).");
                }

                Buffer.MemoryCopy(
                    (void*)(_pendingReceiveBuffer + sizeof(FilterManagerNativeMethods.NativeFilterMessageHeader)),
                    (void*)messageBuffer,
                    messageBufferSize,
                    (transferred - sizeof(FilterManagerNativeMethods.NativeFilterMessageHeader)));

                ClearPendingReceiveState();

                return 1;
            }

            int receivedMessageBufferSize =
                sizeof(FilterManagerNativeMethods.NativeFilterMessageHeader) + (int)messageBufferSize;

            IntPtr receivedMessageBuffer = IntPtr.Zero;
            IntPtr receiveOverlapped = IntPtr.Zero;
            EventWaitHandle? eventHandle = null;

            try
            {
                eventHandle = new EventWaitHandle(false, EventResetMode.ManualReset);

                receivedMessageBuffer = Marshal.AllocHGlobal(receivedMessageBufferSize + sizeof(NativeOverlapped));
                receiveOverlapped = receivedMessageBuffer + receivedMessageBufferSize;

                // Zero the OVERLAPPED memory.
                new Span<byte>((void*)receiveOverlapped, sizeof(NativeOverlapped)).Clear();

                ((NativeOverlapped*)receiveOverlapped)->EventHandle = eventHandle.SafeWaitHandle.DangerousGetHandle();

                long hr = FilterManagerNativeMethods.filter_get_message(
                    receivePortHandle,
                    receivedMessageBuffer,
                    (uint)receivedMessageBufferSize,
                    receiveOverlapped);

                int win32 = HResultToWin32((int)hr);

                if (win32 != ErrorIoPending)
                {
                    throw new Win32Exception(win32, $"FilterGetMessage failed. hr=0x{hr:X8}");
                }

                _pendingReceiveBuffer = receivedMessageBuffer;
                _pendingReceiveOverlapped = receiveOverlapped;
                _receiveEventHandle = eventHandle;

                // Ownership transferred to fields.
                receivedMessageBuffer = IntPtr.Zero;
                receiveOverlapped = IntPtr.Zero;
                eventHandle = null;

                Volatile.Write(ref _receivePending, 1);

                return readSuccess;
            }
            catch
            {
                if (receivedMessageBuffer != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(receivedMessageBuffer);
                }

                eventHandle?.Dispose();

                throw;
            }
        }
        finally
        {
            ExitOperation();
        }
    }

    private void ClearPendingReceiveState()
    {
        IntPtr pendingReceiveBuffer = _pendingReceiveBuffer;
        _pendingReceiveBuffer = IntPtr.Zero;
        _pendingReceiveOverlapped = IntPtr.Zero;

        EventWaitHandle? receiveEventHandle = _receiveEventHandle;
        _receiveEventHandle = null;

        Volatile.Write(ref _receivePending, 0);

        if (pendingReceiveBuffer != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(pendingReceiveBuffer);
        }

        receiveEventHandle?.Dispose();
    }

    private static int HResultToWin32(int hr)
    {
        return hr switch
        {
            >= 0 => 0,
            _ => hr & 0xFFFF
        };
    }

    private void EnterOperation()
    {
        if (Volatile.Read(ref _lifecycleState) != 0)
        {
            throw new ObjectDisposedException(nameof(ConnectionService));
        }

        int activeOperationCount = Interlocked.Increment(ref _activeOperations);

        if (activeOperationCount == 1)
        {
            _noActiveOperationsEvent.Reset();
        }

        if (Volatile.Read(ref _lifecycleState) != 0)
        {
            ExitOperation();

            throw new ObjectDisposedException(nameof(ConnectionService));
        }
    }

    private void ExitOperation()
    {
        int remainingOperationCount = Interlocked.Decrement(ref _activeOperations);

        if (remainingOperationCount <= 0)
        {
            _noActiveOperationsEvent.Set();
        }
    }

    private async Task<MinifilterConnectionResult> ConnectPortAsync(
        PortKind portKind,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();

        await _connectionLock.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            ThrowIfDisposed();

            MinifilterPortHandle? existingHandle = GetPortHandle(portKind);

            if (existingHandle is { IsInvalid: false })
            {
                return MinifilterConnectionResult.AlreadyConnected;
            }

            string communicationPortName = GetPortName(portKind);
            ReadOnlyMemory<byte> connectionContextBuffer = CreateConnectionContextForPort(portKind, cancellationToken);

            var (result, newHandle) = ConnectCommunicationPort_NoLock(
                communicationPortName,
                connectionContextBuffer);

            ReplacePortHandle_NoLock(portKind, newHandle);

            return result;
        }
        finally
        {
            _connectionLock.Release();
        }
    }

    private static string GetPortName(PortKind portKind)
    {
        return portKind switch
        {
            PortKind.SendToKernel => CommunicationPortSendMessageToKernel,
            PortKind.ReceiveFromKernel => CommunicationPortReceiveMessageFromKernel,
            _ => throw new ArgumentOutOfRangeException(nameof(portKind), portKind, "Unsupported port kind."),
        };
    }

    private ReadOnlyMemory<byte> CreateConnectionContextForPort(
        PortKind portKind,
        CancellationToken cancellationToken)
    {
        return portKind switch
        {
            PortKind.SendToKernel => CreateEncryptedConnectionContext(cancellationToken),
            PortKind.ReceiveFromKernel => ReadOnlyMemory<byte>.Empty,
            _ => throw new ArgumentOutOfRangeException(nameof(portKind), portKind, "Unsupported port kind."),
        };
    }

    private MinifilterPortHandle? GetPortHandle(PortKind portKind)
    {
        return portKind switch
        {
            PortKind.SendToKernel => _sendToKernelPortHandle,
            PortKind.ReceiveFromKernel => _receiveFromKernelPortHandle,
            _ => throw new ArgumentOutOfRangeException(nameof(portKind), portKind, "Unsupported port kind."),
        };
    }

    private void ReplacePortHandle_NoLock(PortKind portKind, MinifilterPortHandle newHandle)
    {
        MinifilterPortHandle? oldHandle;

        switch (portKind)
        {
            case PortKind.SendToKernel:
                oldHandle = _sendToKernelPortHandle;
                _sendToKernelPortHandle = newHandle;

                break;

            case PortKind.ReceiveFromKernel:
                oldHandle = _receiveFromKernelPortHandle;
                _receiveFromKernelPortHandle = newHandle;

                break;

            default:
                newHandle.Dispose();

                throw new ArgumentOutOfRangeException(nameof(portKind), portKind, "Unsupported port kind.");
        }

        try
        {
            oldHandle?.Dispose();
        }
        catch (Exception exceptionObject)
        {
            Logger.Warning(exceptionObject, "MINIFILTER: Failed to dispose previous port handle for {PortKind}.", portKind);
        }
    }

    /// <summary>
    /// Connects to a minifilter communication port.
    /// This method must be called only while holding _connectionLock.
    /// </summary>
    private static (MinifilterConnectionResult Result, MinifilterPortHandle Handle) ConnectCommunicationPort_NoLock(
        string communicationPortName,
        ReadOnlyMemory<byte> connectionContextBuffer)
    {
        if (string.IsNullOrWhiteSpace(communicationPortName))
        {
            throw new ArgumentException("Communication port name is null or empty.", nameof(communicationPortName));
        }

        MinifilterPortHandle handle;
        long hResult;

        if (connectionContextBuffer.IsEmpty)
        {
            hResult = FilterManagerNativeMethods.filter_connect_communication_port(
                communicationPortName,
                IntPtr.Zero,
                0,
                out handle);
        }
        else
        {
            unsafe
            {
                fixed (byte* contextPointer = connectionContextBuffer.Span)
                {
                    hResult = FilterManagerNativeMethods.filter_connect_communication_port(
                        communicationPortName,
                        (IntPtr)contextPointer,
                        checked((uint)connectionContextBuffer.Length),
                        out handle);
                }
            }
        }

        if (hResult < 0 || handle is null || handle.IsInvalid)
        {
            handle?.Dispose();

            Logger.Error(
                "MINIFILTER: Connection failed: port={PortName} HRESULT=0x{HR:X8}",
                communicationPortName,
                hResult);

            throw new InvalidOperationException(
                $"Failed to connect to port '{communicationPortName}'. HRESULT=0x{hResult:X8}");
        }

        Logger.Information("MINIFILTER: Connected to minifilter port {PortName}.", communicationPortName);

        return (MinifilterConnectionResult.ConnectedAndAuthenticated, handle);
    }

    /// <summary>
    /// Builds the encrypted connection context sent during communication-port connection.
    /// </summary>
    private byte[] CreateEncryptedConnectionContext(CancellationToken cancellationToken)
    {
        string databaseNativeNtPathLowercase = PathTranslator.DosPathToNtPath(DatabasePath);

        if (string.IsNullOrWhiteSpace(databaseNativeNtPathLowercase))
        {
            throw new InvalidOperationException("Database NT path translation failed.");
        }

        HashSet<string> shieldedPathSet = new(StringComparer.OrdinalIgnoreCase);

        JsonReadService.ReadShieldedPaths(shieldedPathSet);

        List<PayloadBuilders.ConnectionContextPathAccessEntry> normalizedEntries =
            new(shieldedPathSet.Count);

        foreach (string dosPath in shieldedPathSet)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (string.IsNullOrWhiteSpace(dosPath))
            {
                continue;
            }

            string nativeNtPathLowercase = PathTranslator.DosPathToNtPath(dosPath);

            if (string.IsNullOrWhiteSpace(nativeNtPathLowercase))
            {
                throw new InvalidOperationException($"Failed to convert path '{dosPath}' to NT path.");
            }

            normalizedEntries.Add(
                new PayloadBuilders.ConnectionContextPathAccessEntry(
                    nativeNtPathLowercase,
                    (uint)MessageContract.AccessPolicy.AllButDelete));
        }

        PayloadBuilders.PayloadBuildResult payloadResult =
            PayloadBuilders.BuildConnectionContextPayload(
                databaseNativeNtPathLowercase,
                normalizedEntries);

        return MessageBuilders.BuildMessage(
            MessageContract.PayloadType.ConnectionContext,
            payloadResult.Payload.Span,
            payloadResult.ItemCount,
            MessageBuilders.MessageProtection.EncryptedSigned);
    }

    /// <summary>
    /// Disposes the service and releases all owned communication-port handles.
    /// New operations are rejected first, then disposal waits for active operations to finish.
    /// </summary>
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _lifecycleState, 1, 0) != 0)
        {
            return;
        }

        _connectionLock.Wait();

        try
        {
            _noActiveOperationsEvent.Wait();

            try
            {
                _sendToKernelPortHandle?.Dispose();
            }
            catch (Exception exceptionObject)
            {
                Logger.Warning(exceptionObject, "MINIFILTER: Failed to dispose send-to-kernel port handle.");
            }

            try
            {
                _receiveFromKernelPortHandle?.Dispose();
            }
            catch (Exception exceptionObject)
            {
                Logger.Warning(exceptionObject, "MINIFILTER: Failed to dispose receive-from-kernel port handle.");
            }

            ClearPendingReceiveState();

            _sendToKernelPortHandle = null;
            _receiveFromKernelPortHandle = null;

            Volatile.Write(ref _lifecycleState, 2);
        }
        finally
        {
            _connectionLock.Release();
            _connectionLock.Dispose();
            _noActiveOperationsEvent.Dispose();
            GC.SuppressFinalize(this);
        }
    }

    /// <summary>
    /// Throws ObjectDisposedException if the service is disposing or already disposed.
    /// </summary>
    private void ThrowIfDisposed()
    {
        if (Volatile.Read(ref _lifecycleState) != 0)
        {
            throw new ObjectDisposedException(nameof(ConnectionService));
        }
    }
}