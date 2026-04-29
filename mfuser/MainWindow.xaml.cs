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

namespace mfuser
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        // Bound to the upper-left ListView. ObservableCollection auto-updates the UI
        // on Add/Remove; OperationEntry implements INotifyPropertyChanged so
        // updating Status (etc.) updates the row automatically too.
        public ObservableCollection<OperationEntry> Operations { get; }
            = new ObservableCollection<OperationEntry>();

        // Backing storage for log entries.
        public ObservableCollection<LogEntry> Logs { get; }
            = new ObservableCollection<LogEntry>();

        // A CollectionView is a "view" over a collection that supports filtering,
        // sorting, and grouping without modifying the underlying list.
        private ICollectionView _logsView;

        // Currently-selected log filter.
        private LogFilter _currentFilter = LogFilter.All;

        // The communication-layer wrapper.
        private readonly IKernelComm _kernel;

        public MainWindow()
        {
            InitializeComponent();

            // ---- Operations list: load any persisted entries ----
            foreach (var op in OperationStore.Load())
                Operations.Add(op);

            OperationsList.ItemsSource = Operations;

            // ---- Logs list with filtering ----
            _logsView = CollectionViewSource.GetDefaultView(Logs);
            _logsView.Filter = LogFilterPredicate; // return true/false per item
            LogList.ItemsSource = _logsView;

            UpdateFilterButtonStyles();
            UpdateLogCountText();

            // ---- Comm layer ----
            _kernel = new KernelComm();
            _kernel.LogReceived += OnKernelLogReceived;
            _kernel.Start();
        }

        // =================================================================
        // Submit flow
        // =================================================================
        // When the user clicks Submit(or presses Enter in the path box),
        // SubmitCurrentInput() runs:
        //  - it validates the path,
        //  - reads the selected operation,
        //  - creates an OperationEntry row with status "Sending...",
        //  - calls _kernel.SendOperation(path, op),
        //  - and updates the row's status based on the result.

        private void SubmitButton_Click(object sender, RoutedEventArgs e)
            => SubmitCurrentInput();

        // Allow pressing Enter inside the path TextBox to submit.
        private void PathTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter) SubmitCurrentInput();
        }

        private void SubmitCurrentInput()
        {
            var path = PathTextBox.Text?.Trim();
            if (string.IsNullOrWhiteSpace(path))
            {
                MessageBox.Show("Path cannot be empty.", "Validation",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var op = (OperationComboBox.SelectedItem as ComboBoxItem)?
                .Content?.ToString() ?? "shield";

            var entry = new OperationEntry
            {
                Index = Operations.Count + 1,
                Path = path,
                Operation = op,
                Status = "Sending..."
            };
            Operations.Add(entry);

            try
            {
                bool ok = _kernel.SendOperation(path, op);
                // Because OperationEntry implements INotifyPropertyChanged,
                // simply setting Status updates the UI - no Items.Refresh() needed.
                entry.Status = ok ? "Sent" : "Failed";
                AddLog($"[UI] {op} {path} -> {entry.Status}",
                    ok ? Brushes.LightGreen : Brushes.OrangeRed,
                    ok ? LogLevel.Info : LogLevel.Error);
            }
            catch (Exception ex)
            {
                entry.Status = "Error";
                AddLog($"[UI] Exception: {ex.Message}", Brushes.OrangeRed, LogLevel.Error);
            }

            PathTextBox.Clear();
            PathTextBox.Focus();
        }

        // =================================================================
        // Toggle flow - double-click a row to flip shield <-> unshield
        // =================================================================
        // We only toggle rows whose last operation actually went through ("Sent"),
        // because if the previous call failed or is still in flight, we don't
        // really know what state the kernel is in for that path.
        private void OperationsList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            // Make sure the click landed on an actual row, not on the empty area
            // below the rows or on the GridView header.
            if (!(e.OriginalSource is DependencyObject src)) return;
            var row = FindAncestor<ListViewItem>(src);
            if (row == null) return;

            if (!(row.DataContext is OperationEntry entry)) return;

            // Skip rows the user shouldn't be flipping.
            if (entry.Status == "Sending...")
            {
                AddLog("[UI] Toggle ignored: previous call still in flight.",
                    Brushes.Khaki, LogLevel.Warning);
                return;
            }
            if (entry.Status == "Failed" || entry.Status == "Error")
            {
                var resp = MessageBox.Show(
                    $"This row's last status is '{entry.Status}'. The kernel state "
                    + "for this path may be uncertain. Toggle anyway?",
                    "Confirm toggle", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (resp != MessageBoxResult.Yes) return;
            }

            // Flip the operation: shield <-> unshield.
            // Anything that isn't "shield" is treated as unshielded, so a flip
            // always lands us in a defined state.
            var newOp = string.Equals(entry.Operation, "shield",
                StringComparison.OrdinalIgnoreCase) ? "unshield" : "shield";

            // Capture the path for logging in case the entry is mutated below.
            var path = entry.Path;
            entry.Operation = newOp;
            entry.Status = "Sending...";

            try
            {
                bool ok = _kernel.SendOperation(path, newOp);
                entry.Status = ok ? "Sent" : "Failed";
                AddLog($"[UI] toggle {newOp} {path} -> {entry.Status}",
                    ok ? Brushes.LightGreen : Brushes.OrangeRed,
                    ok ? LogLevel.Info : LogLevel.Error);
            }
            catch (Exception ex)
            {
                entry.Status = "Error";
                AddLog($"[UI] toggle exception: {ex.Message}",
                    Brushes.OrangeRed, LogLevel.Error);
            }
        }

        // Walk up the visual tree to find a parent of a given type.
        // Needed because the click's OriginalSource is usually a TextBlock
        // inside the row, not the ListViewItem itself.
        private static T FindAncestor<T>(DependencyObject current) where T : DependencyObject
        {
            while (current != null)
            {
                if (current is T t) return t;
                current = VisualTreeHelper.GetParent(current);
            }
            return null;
        }

        // =================================================================
        // Browse buttons - one for files, one for folders
        // =================================================================
        private void BrowseFileButton_Click(object sender, RoutedEventArgs e)
        {
            var dlg = new OpenFileDialog
            {
                Title = "Select a file to shield/unshield",
                Filter = "All files (*.*)|*.*",
                CheckFileExists = true
            };
            if (dlg.ShowDialog(this) == true)
                PathTextBox.Text = dlg.FileName;
        }

        private void BrowseFolderButton_Click(object sender, RoutedEventArgs e)
        {
            // OpenFolderDialog is the modern WPF folder picker (.NET 8+).
            // For older targets, swap to System.Windows.Forms.FolderBrowserDialog
            // or Ookii.Dialogs.Wpf.VistaFolderBrowserDialog.
            var dlg = new OpenFolderDialog
            {
                Title = "Select a folder to shield/unshield"
            };
            if (dlg.ShowDialog(this) == true)
                PathTextBox.Text = dlg.FolderName;
        }

        // =================================================================
        // Log handling
        // =================================================================
        // The kernel communication layer raises a LogReceived event for every log line.
        // The UI subscribes once in the constructor. Because the event probably fires on a background thread(kernel reader thread, named-pipe thread, etc.),
        // the handler wraps the actual UI update in Dispatcher.Invoke(...) — this is essential, otherwise you'll get cross-thread exceptions when modifying Logs.
        // Each log line is timestamped and color-coded based on keywords (error/fail - red, warn - yellow, shield/unshield - blue).
        // The list is capped at 5000 entries to keep memory bounded, and auto-scroll is honored if the checkbox is on.
        // OnClosed unsubscribes and stops the comm layer cleanly when the window closes.

        private void OnKernelLogReceived(object sender, string logLine)
        {
            // Marshal to UI thread - kernel events can fire on any thread.
            Dispatcher.Invoke(() =>
            {
                var (color, level) = ClassifyLog(logLine);
                AddLog(logLine, color, level);
            });
        }

        private void AddLog(string text, Brush color, LogLevel level)
        {
            Logs.Add(new LogEntry
            {
                Display = $"[{DateTime.Now:HH:mm:ss}] {text}",
                Color = color,
                Level = level
            });

            const int maxLogs = 5000;
            while (Logs.Count > maxLogs) Logs.RemoveAt(0);

            UpdateLogCountText();

            if (AutoScrollCheckBox.IsChecked == true)
                LogScrollViewer.ScrollToEnd();
        }

        private static (Brush color, LogLevel level) ClassifyLog(string line)
        {
            if (string.IsNullOrEmpty(line)) return (Brushes.LightGray, LogLevel.Info);
            var lower = line.ToLowerInvariant();
            if (lower.Contains("error") || lower.Contains("fail"))
                return (Brushes.OrangeRed, LogLevel.Error);
            if (lower.Contains("warn"))
                return (Brushes.Khaki, LogLevel.Warning);
            if (lower.Contains("shield") || lower.Contains("unshield"))
                return (Brushes.LightSkyBlue, LogLevel.Info);
            return (Brushes.LightGray, LogLevel.Info);
        }

        private void ClearLogsButton_Click(object sender, RoutedEventArgs e)
        {
            Logs.Clear();
            UpdateLogCountText();
        }

        private void ClearOperationsButton_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show(
                "Clear all submitted operations? This cannot be undone.",
                "Confirm clear", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result == MessageBoxResult.Yes)
                Operations.Clear();
        }

        // =================================================================
        // Filter buttons
        // =================================================================
        private void FilterButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button b && b.Tag is string tag &&
                Enum.TryParse<LogFilter>(tag, out var f))
            {
                _currentFilter = f;
                _logsView.Refresh();
                UpdateFilterButtonStyles();
                UpdateLogCountText();
            }
        }

        private bool LogFilterPredicate(object obj)
        {
            if (!(obj is LogEntry log)) return false;
            switch (_currentFilter)
            {
                case LogFilter.Errors: return log.Level == LogLevel.Error;
                case LogFilter.Warnings:
                    return log.Level == LogLevel.Warning
                        || log.Level == LogLevel.Error;
                default: return true;
            }
        }

        private void UpdateFilterButtonStyles()
        {
            Highlight(FilterAllButton, _currentFilter == LogFilter.All);
            Highlight(FilterWarningsButton, _currentFilter == LogFilter.Warnings);
            Highlight(FilterErrorsButton, _currentFilter == LogFilter.Errors);
        }

        private static void Highlight(Button btn, bool active)
        {
            btn.Background = active
                ? new SolidColorBrush(Color.FromRgb(0x0E, 0x63, 0x9C))  // active blue
                : new SolidColorBrush(Color.FromRgb(0x3A, 0x3A, 0x3D)); // muted gray
        }

        private void UpdateLogCountText()
        {
            int shown = 0;
            foreach (var _ in _logsView) shown++;
            LogCountText.Text = $"({shown}/{Logs.Count})";
        }

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
            catch { /* best-effort */ }

            _kernel.LogReceived -= OnKernelLogReceived;
            _kernel.Stop();
            base.OnClosed(e);
        }
    }
}
