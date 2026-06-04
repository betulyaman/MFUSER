using mfuser.Models;
using Serilog;

namespace mfuser.Services;

/// <summary>
/// Abstraction over the kernel communication layer.
/// </summary>
public interface IKernelComm
{
    /// <summary>Raised whenever the kernel sends a log line. May fire on a background thread.</summary>
    event EventHandler<string>? LogReceived;

    /// <summary>
    /// Raised when the minifilter reports a blocked operation on a shielded file. 
    /// Subscribers decide whether to unshield (typically by prompting the user).
    /// </summary>
    event EventHandler<MessageContract.UnauthorizedOperationInfo>? UnauthorizedOperationDetected;

    /// <summary>Open the channel and start listening for kernel logs.</summary>
    void Start();

    /// <summary>Close the channel.</summary>
    void Stop();

    /// <summary>
    /// Send a (path, operation, mode) tuple down to the kernel. Folder paths
    /// are expanded to (folder + every file under it) and submitted as a
    /// single batched policy-sync message (or as few messages as the wire
    /// size cap allows). All expanded paths share the same mode.
    ///
    /// <paramref name="mode"/> is irrelevant for an Unshield (kernel ignores
    /// rights on Remove); callers may pass <see cref="ShieldMode.LockInPlace"/>
    /// as a default in that case.
    /// </summary>
    /// <returns>
    /// <c>success</c>: true iff every path was acknowledged by the driver.
    /// <c>pathsSucceeded</c>/<c>pathsFailed</c>: how many paths got through vs
    /// failed. For a single-path submit they're 1/0 or 0/1.
    /// </returns>
    (bool success, int pathsSucceeded, int pathsFailed) SendOperation(
        string path,
        string operation,
        ShieldMode mode);

    /// <summary>
    /// Add or remove a trusted-process image path. The kernel grants the
    /// trusted half of a file's access-right bitmask to callers whose image
    /// path matches an entry here.
    /// </summary>
    Task<bool> SendTrustedProcessOperationAsync(string imagePath, TrustedProcessOperation operation, CancellationToken cancellationToken);
}

/// <summary>
/// Owns the lifecycle of the minifilter ConnectionService, PolicySyncService,
/// and Listener, and forwards their notifications to UI subscribers via LogReceived.
/// </summary>
public sealed class KernelComm : IKernelComm
{
    private static readonly ILogger Logger = Log.ForContext<KernelComm>();

    // Spec: kernel-boot snapshot files are checked for pending updates every
    // 30 seconds (policy_snapshot.bin and trusted_processes_snapshot.bin).
    private static readonly TimeSpan SnapshotPollInterval = TimeSpan.FromSeconds(30);

    public event EventHandler<string>? LogReceived;
    public event EventHandler<MessageContract.UnauthorizedOperationInfo>? UnauthorizedOperationDetected;

    private CancellationTokenSource? _readerCts;
    private Task? _listenerTask;
    private Task? _bootstrapTask;
    private Task? _snapshotPollTask;

    private ConnectionService? _connectionService;
    private PolicySyncService? _policySyncService;
    private TrustedProcessService? _trustedProcessService;
    private Listener? _listener;

    public void Start()
    {
        if (_readerCts is not null) return; // already started

        _readerCts = new CancellationTokenSource();
        CancellationToken token = _readerCts.Token;

        _connectionService = new ConnectionService();
        _policySyncService = new PolicySyncService(_connectionService);
        _trustedProcessService = new TrustedProcessService(_connectionService);
        _listener = new Listener(_connectionService);
        _listener.MinifilterLogEmitted += OnMinifilterLogEmitted;
        _listener.UnauthorizedOperationDetected += OnUnauthorizedOperationDetected;

        _bootstrapTask = Task.Run(() => ConnectAndStartListenerAsync(token), token);
        _snapshotPollTask = Task.Run(() => PollKernelBootSnapshotsAsync(token), token);

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

            Task[] outstanding = new[] { _bootstrapTask, _listenerTask, _snapshotPollTask }
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
            _trustedProcessService = null;

            cts.Dispose();
            _bootstrapTask = null;
            _listenerTask = null;
            _snapshotPollTask = null;
        }

        LogReceived?.Invoke(this, "Kernel channel closed.");
    }

    public (bool success, int pathsSucceeded, int pathsFailed) SendOperation(
        string path,
        string operation,
        ShieldMode mode)
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


        PolicySyncService? policy = _policySyncService;
        if (policy is null)
        {
            Logger.Warning("MINIFILTER: SendOperation called before Start; ignoring.");
            return (false, 0, 0);
        }

        // The minifilter matches per-path, so a folder must be expanded:
        // the folder path itself AND every file under it are sent. For a
        // single-file submission the list contains just the file.
        string[] paths = PathExpander.ExpandToShieldPaths(path).ToArray();

        if (paths.Length == 0)
        {
            Logger.Information("MINIFILTER: No paths to send for {Path}; ignoring.", path);
            return (false, 0, 0);
        }

        // Single batched policy-sync call. PolicySyncService chunks internally
        // when the cumulative payload would exceed the per-message wire cap;
        // each chunk is one encrypted+signed message. A throw means the entire
        // batch (all `paths.Length` paths) failed.
        try
        {
            policy.InformDriver(paths, shieldOperationType, mode);
            return (true, paths.Length, 0);
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "MINIFILTER: InformDriver failed. Path: {Path}, Op: {Operation}, Mode: {Mode}", path, operation, mode);
            return (false, 0, paths.Length);
        }
    }

    public async Task<bool> SendTrustedProcessOperationAsync(
        string imagePath,
        TrustedProcessOperation operation,
        CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            throw new ArgumentException("Image path cannot be null or empty.", nameof(imagePath));
        }

        TrustedProcessService? service = _trustedProcessService;
        if (service is null)
        {
            Logger.Warning("MINIFILTER: SendTrustedProcessOperationAsync called before Start; ignoring.");
            return false;
        }

        try
        {
            return await service.SendAsync(imagePath, operation, cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "MINIFILTER: Trusted-process send failed. Image: {ImagePath}, Op: {Operation}", imagePath, operation);
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

            TrustedProcessService? trustedProcesses = _trustedProcessService;
            if (trustedProcesses is not null)
            {
                try
                {
                    await trustedProcesses.ReplayAllAsync(token).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (token.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    Logger.Error(ex, "MINIFILTER: Trusted-process replay failed at startup.");
                }
            }

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

    private async Task PollKernelBootSnapshotsAsync(CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(SnapshotPollInterval, token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }

            try
            {
                await PolicySnapshotService.UpdateAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "MINIFILTER: Periodic policy_snapshot.bin update failed.");
            }

            // Same cadence for the trusted-process snapshot. Independent
            // dirty flag, independent semaphore, so a failure here can't
            // starve the policy snapshot and vice versa.
            try
            {
                await TrustedProcessSnapshotService.UpdateAsync(token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                return;
            }
            catch (Exception ex)
            {
                Logger.Error(ex, "MINIFILTER: Periodic trusted_processes_snapshot.bin update failed.");
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
    /// Forwards the listener's unauthorized-op notification up to subscribers
    /// (typically the UI). Ask the user and, if confirmed, call SendOperation
    /// with operation = "unshield".
    /// </summary>
    private void OnUnauthorizedOperationDetected(object? sender, MessageContract.UnauthorizedOperationInfo op)
    {
        LogReceived?.Invoke(this, $"[kernel] UNAUTHORIZED {op.MinifilterOperationType} on {op.FileName}");

        if (string.IsNullOrWhiteSpace(op.FileName))
        {
            return;
        }

        try
        {
            UnauthorizedOperationDetected?.Invoke(this, op);
        }
        catch (Exception ex)
        {
            Logger.Error(ex, "MINIFILTER: UnauthorizedOperationDetected subscriber threw.");
        }
    }
}
