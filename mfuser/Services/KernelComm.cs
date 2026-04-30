using Serilog;

namespace mfuser.Services;

/// <summary>
/// Abstraction over the kernel communication layer.
/// </summary>
public interface IKernelComm
{
    /// <summary>Raised whenever the kernel sends a log line. May fire on a background thread.</summary>
    event EventHandler<string>? LogReceived;

    /// <summary>Open the channel and start listening for kernel logs.</summary>
    void Start();

    /// <summary>Close the channel.</summary>
    void Stop();

    /// <summary>
    /// Send a (path, operation) pair down to the kernel.
    /// Returns true if the kernel acknowledged the request.
    /// </summary>
    bool SendOperation(string path, string operation);
}

/// <summary>
/// Owns the lifecycle of the minifilter ConnectionService, PolicySyncService,
/// and Listener, and forwards their notifications to UI subscribers via LogReceived.
/// </summary>
public sealed class KernelComm : IKernelComm
{
    private static readonly ILogger Logger = Log.ForContext<KernelComm>();

    // Spec: blacklist.txt is checked for pending updates every 30 seconds.
    private static readonly TimeSpan BlacklistPollInterval = TimeSpan.FromSeconds(30);

    public event EventHandler<string>? LogReceived;

    private CancellationTokenSource? _readerCts;
    private Task? _listenerTask;
    private Task? _bootstrapTask;
    private Task? _blacklistPollTask;

    private ConnectionService? _connectionService;
    private PolicySyncService? _policySyncService;
    private Listener? _listener;

    public void Start()
    {
        if (_readerCts is not null) return; // already started

        _readerCts = new CancellationTokenSource();
        CancellationToken token = _readerCts.Token;

        _connectionService = new ConnectionService();
        _policySyncService = new PolicySyncService(_connectionService);
        _listener = new Listener(_connectionService);
        _listener.MinifilterLogEmitted += OnMinifilterLogEmitted;
        _listener.UnauthorizedOperationDetected += OnUnauthorizedOperationDetected;

        _bootstrapTask = Task.Run(() => ConnectAndStartListenerAsync(token), token);
        _blacklistPollTask = Task.Run(() => PollBlacklistAsync(token), token);

        LogReceived?.Invoke(this, "Kernel channel opening...");
    }

    public void Stop()
    {
        CancellationTokenSource? cts = _readerCts;
        if (cts is null) return;
        _readerCts = null;

        try
        {
            cts.Cancel();

            Task[] outstanding = new[] { _bootstrapTask, _listenerTask, _blacklistPollTask }
                .Where(t => t is not null)
                .Cast<Task>()
                .ToArray();

            if (outstanding.Length > 0)
            {
                try
                {
                    Task.WaitAll(outstanding, TimeSpan.FromSeconds(2));
                }
                catch (AggregateException)
                {
                    // expected on cancel
                }
            }
        }
        finally
        {
            if (_listener is not null)
            {
                _listener.MinifilterLogEmitted -= OnMinifilterLogEmitted;
                _listener.UnauthorizedOperationDetected -= OnUnauthorizedOperationDetected;
                _listener = null;
            }

            try
            {
                _connectionService?.Dispose();
            }
            catch (Exception ex)
            {
                Logger.Warning(ex, "MINIFILTER: Failed to dispose ConnectionService.");
            }
            _connectionService = null;
            _policySyncService = null;

            cts.Dispose();
            _bootstrapTask = null;
            _listenerTask = null;
            _blacklistPollTask = null;
        }

        LogReceived?.Invoke(this, "Kernel channel closed.");
    }

    public bool SendOperation(string path, string operation)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("Path cannot be null, empty, or whitespace.", nameof(path));
        }
        if (string.IsNullOrWhiteSpace(operation))
        {
            throw new ArgumentException("Operation cannot be null, empty, or whitespace.", nameof(operation));
        }

        ShieldOperationType shieldOperationType = string.Equals(operation, "shield", StringComparison.OrdinalIgnoreCase)
            ? ShieldOperationType.Shield
            : ShieldOperationType.Unshield;

        // Mark the blacklist file as dirty and update it in the background.
        // The shutdown path also runs UpdateBlacklistFileAsync as a final flush.
        BlacklistService.MarkBlacklistDirty();
        _ = Task.Run(async () =>
        {
            try
            {
                await BlacklistService.UpdateBlacklistFileAsync(CancellationToken.None).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "MINIFILTER: Background blacklist update failed.");
            }
        });

        // Inform the driver. PolicySyncService throws on transport/wiring
        // problems; translate into a simple bool so the UI can mark "Failed".
        PolicySyncService? policy = _policySyncService;
        if (policy is null)
        {
            Logger.Warning("MINIFILTER: SendOperation called before Start; ignoring.");
            LogReceived?.Invoke(this, $"-> kernel SKIPPED (not started): {operation} {path}");
            return false;
        }

        try
        {
            policy.InformDriver(path, shieldOperationType);
            LogReceived?.Invoke(this, $"-> kernel: {operation} {path}");
            return true;
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "MINIFILTER: Failed to inform driver. Path: {Path}, Op: {Operation}", path, operation);
            LogReceived?.Invoke(this, $"-> kernel FAILED: {operation} {path} ({ex.Message})");
            return false;
        }
    }

    /// <summary>
    /// Spec lifecycle: SEND port (with encrypted+signed connection context)
    /// must be opened first, then the RECEIVE port. After both ports are
    /// connected we start the listener.
    /// </summary>
    private async Task ConnectAndStartListenerAsync(CancellationToken token)
    {
        ConnectionService? connection = _connectionService;
        Listener? listener = _listener;
        if (connection is null || listener is null) return;

        try
        {
            await connection.ConnectSendMessagePortToKernelAsync(token).ConfigureAwait(false);
            await connection.ConnectReceiveMessagePortFromKernelAsync(token).ConfigureAwait(false);

            _listenerTask = Task.Run(() => listener.RunAsync(token), token);

            LogReceived?.Invoke(this, "Kernel channel opened.");
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
            // shutting down
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "MINIFILTER: Failed to bring up kernel channel.");
            LogReceived?.Invoke(this, $"Kernel channel ERROR: {ex.Message}");
        }
    }

    private async Task PollBlacklistAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(BlacklistPollInterval, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            try
            {
                await BlacklistService.UpdateBlacklistFileAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "MINIFILTER: Periodic blacklist update failed.");
            }
        }
    }

    private void OnMinifilterLogEmitted(object? sender, PayloadParser.ParsedLogEntry logEntry)
    {
        string severity = logEntry.LogType switch
        {
            MessageContract.LogType.Failure => "ERROR",
            MessageContract.LogType.Warning => "WARN",
            MessageContract.LogType.Info => "INFO",
            _ => "LOG",
        };

        LogReceived?.Invoke(this, $"[kernel/{severity}] {logEntry.Message}");
    }

    /// <summary>
    /// Spec: when the minifilter reports a blocked operation, the agent
    /// triggers the unshield flow for that path and notifies the driver so
    /// the file can be removed from protection.
    /// </summary>
    private void OnUnauthorizedOperationDetected(object? sender, MessageContract.UnauthorizedOperationInfo op)
    {
        LogReceived?.Invoke(this, $"[kernel] UNAUTHORIZED {op.MinifilterOperationType} on {op.FileName}");

        PolicySyncService? policy = _policySyncService;
        if (policy is null || string.IsNullOrWhiteSpace(op.FileName))
        {
            return;
        }

        try
        {
            policy.InformDriver(op.FileName, ShieldOperationType.Unshield);
            BlacklistService.MarkBlacklistDirty();
            LogReceived?.Invoke(this, $"-> kernel: auto-unshield {op.FileName}");
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "MINIFILTER: Auto-unshield failed for {Path}.", op.FileName);
            LogReceived?.Invoke(this, $"-> kernel: auto-unshield FAILED {op.FileName} ({ex.Message})");
        }
    }
}
