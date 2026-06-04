using mfuser.Models;
using mfuser.Services;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
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

    /// <summary>Backing storage for every log entry, in arrival order.
    /// Logs that don't pass <see cref="_currentFilter"/> are still kept here
    /// so a filter change can re-show them; only the FlowDocument paragraphs
    /// represent the currently visible subset.</summary>
    public ObservableCollection<LogEntry> Logs { get; } = new();

    // Currently-selected log filter.
    private LogFilter _currentFilter = LogFilter.All;

    // Cached count of entries the filter currently lets through. Avoids re-enumerating
    // Logs on every log line.
    private int _filteredLogCount;

    // Stops asking the user with N dialogs files under one shielded folder. 
    private readonly HashSet<string> _promptedSubjects = new(StringComparer.OrdinalIgnoreCase);

    // The communication-layer wrapper.
    private readonly IKernelComm _kernel;

    public MainWindow()
    {
        InitializeComponent();

        // ---- Operations list: load any persisted entries ----
        List<OperationEntry> loaded = OperationStore.Load();
        foreach (OperationEntry op in loaded)
        {
            Operations.Add(op);
        }

        OperationsList.ItemsSource = Operations;

        // Tooltip exposes the resolved JSON path so users can copy it without
        // digging in source.
        RefreshOperationsButton.ToolTip = $"Reload operations from disk:\n{OperationStore.FilePath}";

        // ---- Logs pane (RichTextBox) ----
        // RichTextBox renders one Paragraph per filtered log entry; the
        // FlowDocument is built from XAML and we just append/remove blocks.
        UpdateFilterButtonStyles();
        UpdateLogCountText();

        // Surface the load result so the user can tell whether persisted
        // operations were actually picked up (empty file, missing file,
        // corrupt JSON all return 0 entries from Load()).
        if (loaded.Count > 0)
        {
            AddLog(
                $"[UI] Loaded {loaded.Count} persisted operation(s) from {OperationStore.FilePath}",
                ColorOk,
                LogLevel.Info);
        }
        else
        {
            AddLog(
                $"[UI] No persisted operations found at {OperationStore.FilePath} (empty/missing/unreadable)",
                ColorWarning,
                LogLevel.Warning);
        }

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
    //
    // Many ops for files under the same shielded folder coalesce into ONE
    // prompt for the folder. We resolve the closest currently-shielded
    // ancestor (folder or, failing that, the file itself), and remember it
    // in _promptedSubjects so subsequent ops for files under the same
    // ancestor are dropped silently. The dedupe entry is cleared whenever
    // the user manually shields/unshields that path so re-shielding the
    // same folder later re-arms the prompt.
    private void OnKernelUnauthorizedOperationDetected(object? sender, MessageContract.UnauthorizedOperationInfo op)
    {
        // Listener events fire on a background thread; marshal to the UI.
        Dispatcher.Invoke(() =>
        {
            // Resolve the prompt subject: the shielded folder containing the
            // file if one exists, otherwise the file itself.
            string subject = JsonReadService.FindShieldedAncestor(op.FileName) ?? op.FileName;

            // Coalesce: one prompt per subject. Subsequent ops for files
            // under the same shielded folder are dropped (logged as info).
            if (!_promptedSubjects.Add(subject))
            {
                AddLog(
                    $"[UI] {op.MinifilterOperationType} on {op.FileName} (already prompted for {subject})",
                    ColorMuted,
                    LogLevel.Info);
                return;
            }

            bool subjectIsFolder =
                !string.Equals(subject, op.FileName, StringComparison.OrdinalIgnoreCase)
                || PathExpander.IsDirectory(subject);

            string promptBody = subjectIsFolder
                ? $"The minifilter blocked a {op.MinifilterOperationType} operation on a file under shielded folder:\n\n{subject}\n\nFile: {op.FileName}\n\nDo you want to unshield this folder (and everything inside)?"
                : $"The minifilter blocked a {op.MinifilterOperationType} operation:\n\n{op.FileName}\n\nDo you want to unshield this path?";

            MessageBoxResult choice = MessageBox.Show(
                promptBody,
                "Unauthorized operation",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);

            if (choice != MessageBoxResult.Yes)
            {
                AddLog($"[UI] User declined unshield for {subject}", ColorWarning, LogLevel.Warning);
                return;
            }

            var entry = new OperationEntry
            {
                Index = Operations.Count + 1,
                Path = subject,
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
    //  - read the selected mode from the ComboBox,
    //  - create an OperationEntry row with status "Sending...",
    //  - call _kernel.SendOperation(path, "shield", mode),
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

        // Selection always shields. Unshield is done by double-clicking the
        // row in the Operations list.
        const string operation = "shield";
        ShieldMode mode = ReadSelectedShieldMode();

        var entry = new OperationEntry
        {
            Index = Operations.Count + 1,
            Path = path,
            Operation = operation,
            Mode = mode,
            Status = "Sending...",
        };
        Operations.Add(entry);

        RunOperationOnEntry(entry, operation, source: "submit");

        PathTextBox.Clear();
        PathTextBox.Focus();
    }

    /// <summary>
    /// Translates the ComboBox's selected index into a <see cref="ShieldMode"/>.
    /// Order in MainWindow.xaml: Lock-in-place (0), Read-only (1), Private (2).
    /// Falls back to <see cref="ShieldMode.LockInPlace"/> if the selection is
    /// out of range (defensive; should not happen with the static ComboBox).
    /// </summary>
    private ShieldMode ReadSelectedShieldMode()
    {
        return ModeComboBox?.SelectedIndex switch
        {
            1 => ShieldMode.ReadOnly,
            2 => ShieldMode.Private,
            _ => ShieldMode.LockInPlace,
        };
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
        // Capture the path and mode locally so the background work is
        // independent of any later mutations to the entry.
        string path = entry.Path;
        ShieldMode mode = entry.Mode;

        // Reset auto-prompt dedupe for this path: any subsequent unauthorized
        // op for files under it should re-prompt (the user just changed their
        // mind about its shield state).
        _promptedSubjects.Remove(path);

        Task.Run(() =>
        {
            try
            {
                (bool ok, int pathsSucceeded, int pathsFailed) = _kernel.SendOperation(path, operation, mode);

                Dispatcher.Invoke(() =>
                {
                    entry.Status = ok ? "Sent" : "Failed";

                    int totalPaths = pathsSucceeded + pathsFailed;
                    string suffix = totalPaths > 1
                        ? (ok
                            ? $" ({totalPaths} paths)"
                            : $" ({pathsSucceeded}/{totalPaths} paths)")
                        : string.Empty;

                    AddLog(
                        $"[UI] {source} {operation} {path} -> {entry.Status}{suffix}",
                        ok ? ColorOk : ColorError,
                        ok ? LogLevel.Info : LogLevel.Error);

                    // Persist immediately so a crash/kill before window-close
                    // doesn't lose this entry. OperationStore.Save marks the
                    // policy snapshot dirty internally; no separate call needed.
                    OperationStore.Save(Operations);

                    // Trigger the encrypted+signed policy_snapshot.bin update
                    // AFTER operations.json is on disk, so JsonReadService
                    // doesn't race the save. Surface the outcome so a
                    // permission/IO failure is visible in the log pane.
                    _ = Task.Run(async () =>
                    {
                        bool wrote = false;
                        Exception? error = null;
                        try
                        {
                            wrote = await PolicySnapshotService.UpdateAsync(CancellationToken.None).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            error = ex;
                        }

                        Dispatcher.Invoke(() =>
                        {
                            if (error is not null)
                            {
                                AddLog($"[UI] policy_snapshot.bin update FAILED: {error.Message}", ColorError, LogLevel.Error);
                            }
                            else if (wrote)
                            {
                                AddLog("[UI] policy_snapshot.bin updated", ColorOk, LogLevel.Info);
                            }
                            else
                            {
                                // The dirty flag was already cleared by an
                                // earlier writer, or the file was clean. Not
                                // an error.
                                AddLog("[UI] policy_snapshot.bin update skipped (no pending changes or already written)", ColorMuted, LogLevel.Info);
                            }
                        });
                    });
                });
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    entry.Status = "Error";
                    AddLog($"[UI] {source} exception: {ex.Message}", ColorError, LogLevel.Error);
                    OperationStore.Save(Operations);
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
            SubmitCurrentInput();
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
            SubmitCurrentInput();
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

        // Append a paragraph for it if the current filter lets it through.
        bool passes = Passes(_currentFilter, level);
        if (passes)
        {
            LogList.Document.Blocks.Add(CreateLogParagraph(entry));
            _filteredLogCount++;
        }

        // Trim the head to keep memory bounded. Remove the matching paragraph
        // (the first one in the document) only when the trimmed entry passed
        // the current filter — otherwise no paragraph exists for it.
        while (Logs.Count > MaxLogEntries)
        {
            LogEntry removed = Logs[0];
            Logs.RemoveAt(0);

            if (Passes(_currentFilter, removed.Level))
            {
                Block? firstBlock = LogList.Document.Blocks.FirstBlock;
                if (firstBlock is not null) LogList.Document.Blocks.Remove(firstBlock);
                _filteredLogCount--;
            }
        }

        UpdateLogCountText();

        if (passes && AutoScrollCheckBox.IsChecked == true)
        {
            LogList.ScrollToEnd();
        }
    }

    /// <summary>Builds a tight, color-coded Paragraph for one log entry.</summary>
    private static Paragraph CreateLogParagraph(LogEntry entry)
    {
        return new Paragraph(new Run(entry.Display) { Foreground = entry.Color })
        {
            Margin = new Thickness(0),
            LineHeight = 14,
        };
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
        LogList.Document.Blocks.Clear();
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

    /// <summary>
    /// Reloads operations from <see cref="OperationStore.FilePath"/>, replacing
    /// the in-memory list. Useful when the JSON file was edited externally or
    /// when the user wants to confirm what's currently on disk.
    /// </summary>
    private void RefreshOperationsButton_Click(object sender, RoutedEventArgs e)
    {
        List<OperationEntry> loaded = OperationStore.Load();

        Operations.Clear();
        foreach (OperationEntry op in loaded)
        {
            Operations.Add(op);
        }

        AddLog(
            $"[UI] Reloaded {loaded.Count} entries from {OperationStore.FilePath}",
            loaded.Count > 0 ? ColorOk : ColorWarning,
            loaded.Count > 0 ? LogLevel.Info : LogLevel.Warning);
    }

    /// <summary>
    /// Opens the modal Trusted Processes management dialog. The dialog runs
    /// against the same KernelComm channel so adds/removes are routed through
    /// the existing encrypted+signed send port.
    /// </summary>
    private void TrustedProcessesButton_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new TrustedProcessesWindow(_kernel)
        {
            Owner = this,
        };
        dlg.ShowDialog();
    }

    /// <summary>
    /// Pops up a dialog listing every path currently under minifilter
    /// protection, with shielded folders expanded into their files —
    /// i.e. exactly what the kernel sees, not just what the user submitted.
    /// </summary>
    private void ViewProtectedFilesButton_Click(object sender, RoutedEventArgs e)
    {
        var paths = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        try
        {
            JsonReadService.ReadShieldedPaths(paths);
        }
        catch (Exception ex)
        {
            MessageBox.Show(
                this,
                $"Failed to enumerate shielded paths:\n\n{ex.Message}",
                "Protected files",
                MessageBoxButton.OK,
                MessageBoxImage.Error);
            return;
        }

        List<string> sortedPaths = paths.OrderBy(p => p, StringComparer.OrdinalIgnoreCase).ToList();

        var listBox = new ListBox
        {
            ItemsSource = sortedPaths,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 12,
            Background = (Brush)new BrushConverter().ConvertFromString("#1E1E1E")!,
            Foreground = Brushes.LightGray,
            BorderThickness = new Thickness(0),
            HorizontalContentAlignment = HorizontalAlignment.Stretch,
        };

        var window = new Window
        {
            Title = $"Protected paths ({sortedPaths.Count})",
            Width = 720,
            Height = 480,
            Owner = this,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Background = (Brush)new BrushConverter().ConvertFromString("#252526")!,
            Content = listBox,
        };

        window.ShowDialog();
    }

    // =================================================================
    // Filter buttons
    // =================================================================
    private void FilterButton_Click(object sender, RoutedEventArgs e)
    {
        if (sender is Button { Tag: string tag } && Enum.TryParse(tag, out LogFilter f))
        {
            _currentFilter = f;
            RebuildLogDocument();
            UpdateFilterButtonStyles();
            UpdateLogCountText();
        }
    }

    /// <summary>
    /// Rebuilds the FlowDocument from <see cref="Logs"/> using the current
    /// filter. Called when the user changes the filter button selection.
    /// </summary>
    private void RebuildLogDocument()
    {
        LogList.Document.Blocks.Clear();
        int count = 0;
        foreach (LogEntry entry in Logs)
        {
            if (Passes(_currentFilter, entry.Level))
            {
                LogList.Document.Blocks.Add(CreateLogParagraph(entry));
                count++;
            }
        }
        _filteredLogCount = count;
    }

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
            PolicySnapshotService.UpdateAsync(CancellationToken.None).GetAwaiter().GetResult();
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
