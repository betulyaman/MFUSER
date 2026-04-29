using Serilog;

public sealed class StartupService : IHostedService
{
    private static readonly ILogger _logger = Log.ForContext<StartupService>();

    private readonly ConnectionService _connectionService;
    private readonly BlacklistService _blacklistService;
    private readonly PolicySyncService _policySyncService;

    private Task? _blacklistLoopTask;
    private readonly CancellationTokenSource _blacklistCts = new();

    public StartupService(ConnectionService connectionService, BlacklistService blacklistService, PolicySyncService policySyncService)
    {
        _connectionService = connectionService ?? throw new ArgumentNullException(nameof(connectionService));
        _blacklistService = blacklistService ?? throw new ArgumentNullException(nameof(blacklistService));
        _policySyncService = policySyncService ?? throw new ArgumentNullException(nameof(policySyncService));
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await _connectionService.ConnectSendMessagePortToKernelAsync(cancellationToken).ConfigureAwait(false);
        await _connectionService.ConnectReceiveMessagePortFromKernelAsync(cancellationToken).ConfigureAwait(false);

        _blacklistLoopTask = RunBlacklistLoopAsync(_blacklistCts.Token);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _blacklistCts.Cancel();

        if (_blacklistLoopTask != null)
        {
            await Task.WhenAny(_blacklistLoopTask, Task.Delay(TimeSpan.FromSeconds(5), cancellationToken));
        }
    }

    private async Task RunBlacklistLoopAsync(CancellationToken cancellationToken)
    {
        using PeriodicTimer timer = new(TimeSpan.FromSeconds(30));

        try
        {
            while (await timer.WaitForNextTickAsync(cancellationToken).ConfigureAwait(false))
            {
                try
                {
                    await _blacklistService.UpdateBlacklistFileAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }
                catch (Exception exceptionObject)
                {
                    _logger.Error(exceptionObject, "MINIFILTER: Error while updating blacklist file.");
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }
}