using mfuser.Models;
using mfuser.Services;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;

namespace mfuser;

/// <summary>
/// Interaction logic for MainWindow.xaml.
/// </summary>
public partial class MainWindow : Window
{
    private const int MaxLogEntries = 5_000;

    private static readonly Brush ColorInfo = Brushes.LightSkyBlue;
    private static readonly Brush ColorOk = Brushes.LightGreen;
    private static readonly Brush ColorWarning = Brushes.Khaki;
    private static readonly Brush ColorError = Brushes.OrangeRed;
    private static readonly Brush ColorMuted = Brushes.LightGray;
    private static readonly Brush ColorActive = new SolidColorBrush(Color.FromRgb(0x0E, 0x63, 0x9C));
    private static readonly Brush ColorInactive = new SolidColorBrush(Color.FromRgb(0x3A, 0x3A, 0x3D));

    /// <summary>
    /// Backing collection for the upper-left ListView. ObservableCollection{T}
    /// auto-updates the UI on add/remove, and OperationEntry is itself
    /// INotifyPropertyChanged, so updating OperationEntry.Status
    /// updates the row automatically too.
    /// </summary>
    public ObservableCollection<OperationEntry> Operations { get; } = new();

    /// <summary>Backing storage for log entries.</summary>
    public ObservableCollection<LogEntry> Logs { get; } = new();

    // A CollectionView is a "view" over a collection that supports filtering,
    // sorting, and grouping without modifying the underlying list.
    private readonly ICollectionView _logsView;

    // Currently-selected log filter.
    private LogFilter _currentFilter = LogFilter.All;

    // Cached count of entries the filter currently lets through. Avoids re-enumerating
    // the view every time we add a log line.
    private int _filteredLogCount;

    // The communication-layer wrapper.
    private readonly IKernelComm _kernel;

    public MainWindow()
    {
        InitializeComponent();

        // ---- Operations list: load any persisted entries ----
        foreach (OperationEntry op in OperationStore.Load())
        {
            Operations.Add(op);
        }

        OperationsList.ItemsSource = Operations;

        // ---- Logs list with filtering ----
        _logsView = CollectionViewSource.GetDefaultView(Logs);
        _logsView.Filter = LogFilterPredicate;
        LogList.ItemsSource = _logsView;

        UpdateFilterButtonStyles();
        UpdateLogCountText();

        // ---- Comm layer ----
        _kernel = new KernelComm();
        _kernel.LogReceived += OnKernelLogReceived;
        _kernel.UnauthorizedOperationDetected += OnKernelUnauthorizedOperationDetected;
        _kernel.Start();
    }

    // =================================================================
    // Unauthorized operation prompt
    // =================================================================
    // The minifilter raises this when it blocks a DELETE/MOVE/RENAME on a
    // shielded file. DO NOT auto-unshield — instead ask the user, and
    // only on Yes do route a normal unshield through SendOperation so a
    // row appears in the Operations list with proper Sent/Failed/Error status.
    private void OnKernelUnauthorizedOperationDetected(object? sender, MessageContract.UnauthorizedOperationInfo op)
    {
        // Listener events fire on a background thread; marshal to the UI.
        Dispatcher.Invoke(() =>
        {
            string detail = string.IsNullOrWhiteSpace(op.TargetName)
                ? op.FileName
                : $"{op.FileName}\n  → {op.TargetName}";

            MessageBoxResult choice = MessageBox.Show(
                $"The minifilter blocked a {op.MinifilterOperationType} operation:\n\n{detail}\n\nDo you want to unshield this path?",
                "Unauthorized operation",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (choice != MessageBoxResult.Yes)
            {
                AddLog($"[UI] User declined unshield for {op.FileName}", ColorWarning, LogLevel.Warning);
                return;
            }

            var entry = new OperationEntry
            {
                Index = Operations.Count + 1,
                Path = op.FileName,
                Operation = "unshield",
                Status = "Sending...",
            };
            Operations.Add(entry);
            RunOperationOnEntry(entry, "unshield", source: "auto-prompt");
        });
    }

    // =================================================================
    // Submit flow
    // =================================================================
    // When the user clicks Submit (or presses Enter in the path box):
    //  - validate the path,
    //  - read the selected operation,
    //  - create an OperationEntry row with status "Sending...",
    //  - call _kernel.SendOperation(path, op),
    //  - update the row's status based on the result.
    private void SubmitButton_Click(object sender, RoutedEventArgs e) => SubmitCurrentInput();

    // Allow pressing Enter inside the path TextBox to submit.
    private void PathTextBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) SubmitCurrentInput();
    }

    private void SubmitCurrentInput()
    {
        string? path = PathTextBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(path))
        {
            MessageBox.Show(
                "Path cannot be empty.",
                "Validation",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        string operation =
            (OperationComboBox.SelectedItem as ComboBoxItem)?.Content?.ToString() ?? "shield";

        var entry = new OperationEntry
        {
            Index = Operations.Count + 1,
            Path = path,
            Operation = operation,
            Status = "Sending...",
        };
        Operations.Add(entry);

        RunOperationOnEntry(entry, operation, source: "submit");

        PathTextBox.Clear();
        PathTextBox.Focus();
    }

    // =================================================================
    // Toggle flow — double-click a row to flip shield <-> unshield
    // =================================================================
    // We only toggle rows whose last operation actually went through ("Sent"),
    // because if the previous call failed or is still in flight, we don't
    // really know what state the kernel is in for that path.
    private void OperationsList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        // Make sure the click landed on an actual row, not on the empty area
        // below the rows or on the GridView header.
        if (e.OriginalSource is not DependencyObject src) return;

        ListViewItem? row = FindAncestor<ListViewItem>(src);
        if (row?.DataContext is not OperationEntry entry) return;

        // Skip rows the user shouldn't be flipping.
        if (entry.Status == "Sending...")
        {
            AddLog(
                "[UI] Toggle ignored: previous call still in flight.",
                ColorWarning,
                LogLevel.Warning);
            return;
        }

        if (entry.Status is "Failed" or "Error")
        {
            MessageBoxResult resp = MessageBox.Show(
                $"This row's last status is '{entry.Status}'. The kernel state for this path may be uncertain. Toggle anyway?",
                "Confirm toggle",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);

            if (resp != MessageBoxResult.Yes) return;
        }

        // Flip the operation: shield <-> unshield.
        // Anything that isn't "shield" is treated as unshielded, so a flip
        // always lands us in a defined state.
        string newOperation = string.Equals(entry.Operation, "shield", StringComparison.OrdinalIgnoreCase)
            ? "unshield"
            : "shield";

        entry.Operation = newOperation;
        entry.Status = "Sending...";
        RunOperationOnEntry(entry, newOperation, source: "toggle");
    }

    /// <summary>
    /// Calls the kernel comm layer for <paramref name="entry"/> and updates the row's
    /// status + emits a UI log line. <paramref name="source"/> just tags the log.
    /// Runs the kernel call on a background task so shielding a folder with
    /// many files (each one is a separate kernel message) doesn't freeze the UI.
    /// </summary>
    private void RunOperationOnEntry(OperationEntry entry, string operation, string source)
    {
        // Capture the path locally so the background work is independent of
        // any later mutations to the entry.
        string path = entry.Path;

        Task.Run(() =>
        {
            try
            {
                bool ok = _kernel.SendOperation(path, operation);

                Dispatcher.Invoke(() =>
                {
                    entry.Status = ok ? "Sent" : "Failed";
                    AddLog(
                        $"[UI] {source} {operation} {path} -> {entry.Status}",
                        ok ? ColorOk : ColorError,
                        ok ? LogLevel.Info : LogLevel.Error);
                });
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    entry.Status = "Error";
                    AddLog($"[UI] {source} exception: {ex.Message}", ColorError, LogLevel.Error);
                });
            }
        });
    }

    // Walk up the visual tree to find a parent of a given type.
    // Needed because the click's OriginalSource is usually a TextBlock
    // inside the row, not the ListViewItem itself.
    private static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match) return match;
            current = VisualTreeHelper.GetParent(current);
        }
        return null;
    }

    // =================================================================
    // Browse buttons — one for files, one for folders
    // =================================================================
    private void BrowseFileButton_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select a file to shield/unshield",
            Filter = "All files (*.*)|*.*",
            CheckFileExists = true,
        };

        if (dlg.ShowDialog(this) == true)
        {
            PathTextBox.Text = dlg.FileName;
        }
    }

    private void BrowseFolderButton_Click(object sender, RoutedEventArgs e)
    {
        // OpenFolderDialog is the modern WPF folder picker (.NET 8+).
        // For older targets, swap to System.Windows.Forms.FolderBrowserDialog
        // or Ookii.Dialogs.Wpf.VistaFolderBrowserDialog.
        var dlg = new OpenFolderDialog { Title = "Select a folder to shield/unshield" };

        if (dlg.ShowDialog(this) == true)
        {
            PathTextBox.Text = dlg.FolderName;
        }
    }

    // =================================================================
    // Log handling
    // =================================================================
    // The kernel comm layer raises LogReceived for every log line. The handler
    // marshals to the UI thread because the event may fire on a background
    // thread (kernel reader, named-pipe thread, etc.). Each line is stamped,
    // color-coded, and capped at MaxLogEntries to bound memory.
    private void OnKernelLogReceived(object? sender, string logLine)
    {
        // Marshal to UI thread - kernel events can fire on any thread.
        Dispatcher.Invoke(() =>
        {
            (Brush color, LogLevel level) = ClassifyLog(logLine);
            AddLog(logLine, color, level);
        });
    }

    private void AddLog(string text, Brush color, LogLevel level)
    {
        var entry = new LogEntry
        {
            Display = $"[{DateTime.Now:HH:mm:ss}] {text}",
            Color = color,
            Level = level,
        };

        Logs.Add(entry);
        if (Passes(_currentFilter, level)) _filteredLogCount++;

        // Trim the head to keep memory bounded.
        while (Logs.Count > MaxLogEntries)
        {
            LogEntry removed = Logs[0];
            if (Passes(_currentFilter, removed.Level)) _filteredLogCount--;
            Logs.RemoveAt(0);
        }

        UpdateLogCountText();

        if (AutoScrollCheckBox.IsChecked == true)
        {
            LogScrollViewer.ScrollToEnd();
        }
    }

    private static (Brush color, LogLevel level) ClassifyLog(string line)
    {
        if (string.IsNullOrEmpty(line)) return (ColorMuted, LogLevel.Info);

        string lower = line.ToLowerInvariant();
        if (lower.Contains("error") || lower.Contains("fail")) return (ColorError, LogLevel.Error);
        if (lower.Contains("warn")) return (ColorWarning, LogLevel.Warning);
        if (lower.Contains("shield") || lower.Contains("unshield")) return (ColorInfo, LogLevel.Info);
        return (ColorMuted, LogLevel.Info);
    }

    private void ClearLogsButton_Click(object sender, RoutedEventArgs e)
    {
        Logs.Clear();
        _filteredLogCount = 0;
        UpdateLogCountText();
    }

    private void ClearOperationsButton_Click(object sender, RoutedEventArgs e)
    {
        MessageBoxResult result = MessageBox.Show(
            "Clear all submitted operations? This cannot be undone.",
            "Confirm clear",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result == MessageBoxResult.Yes) Operations.Clear();
    }

    // =================================================================
    // Filter buttons
    // =================================================================
    private void FilterButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string tag } && Enum.TryParse(tag, out LogFilter f))
        {
            _currentFilter = f;
            _logsView.Refresh();
            RecomputeFilteredCount();
            UpdateFilterButtonStyles();
            UpdateLogCountText();
        }
    }

    private bool LogFilterPredicate(object obj) =>
        obj is LogEntry log && Passes(_currentFilter, log.Level);

    private static bool Passes(LogFilter filter, LogLevel level) => filter switch
    {
        LogFilter.Errors => level == LogLevel.Error,
        LogFilter.Warnings => level is LogLevel.Warning or LogLevel.Error,
        _ => true,
    };

    private void RecomputeFilteredCount()
    {
        int count = 0;
        foreach (LogEntry log in Logs)
        {
            if (Passes(_currentFilter, log.Level)) count++;
        }
        _filteredLogCount = count;
    }

    private void UpdateFilterButtonStyles()
    {
        Highlight(FilterAllButton, _currentFilter == LogFilter.All);
        Highlight(FilterWarningsButton, _currentFilter == LogFilter.Warnings);
        Highlight(FilterErrorsButton, _currentFilter == LogFilter.Errors);
    }

    private static void Highlight(Button btn, bool active) =>
        btn.Background = active ? ColorActive : ColorInactive;

    private void UpdateLogCountText() =>
        LogCountText.Text = $"({_filteredLogCount}/{Logs.Count})";

    // =================================================================
    // Persistence on close
    // =================================================================
    protected override void OnClosed(EventArgs e)
    {
        try
        {
            OperationStore.Save(Operations);
            BlacklistService.UpdateBlacklistFileAsync(CancellationToken.None).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            // Best-effort on shutdown, but at least leave a log breadcrumb.
            System.Diagnostics.Debug.WriteLine($"Shutdown persistence failed: {ex}");
        }

        _kernel.LogReceived -= OnKernelLogReceived;
        _kernel.UnauthorizedOperationDetected -= OnKernelUnauthorizedOperationDetected;
        _kernel.Stop();
        base.OnClosed(e);
    }
}
