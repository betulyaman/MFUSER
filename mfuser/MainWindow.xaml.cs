using mfuser.Models;
using mfuser.Services;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace mfuser
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        // Bound to the upper-left ListView. ObservableCollection auto-updates the UI.
        // ObservableCollection automatically notifies the UI when items are added/removed,
        // so you never have to manually refresh the lists.
        public ObservableCollection<OperationEntry> Operations { get; }
            = new ObservableCollection<OperationEntry>();

        // Bound to the right-side log list.
        public ObservableCollection<LogEntry> Logs { get; }
            = new ObservableCollection<LogEntry>();

        // Your communication-layer wrapper. Replace IKernelComm with your real type.
        private readonly IKernelComm _kernel;

        public MainWindow()
        {
            InitializeComponent();

            OperationsList.ItemsSource = Operations;
            LogList.ItemsSource = Logs;

            // Instantiate (or inject) your existing communication layer.
            _kernel = new IKernelComm();

            // Subscribe to the kernel's log stream BEFORE starting it so we don't miss any.
            _kernel.LogReceived += OnKernelLogReceived;
            _kernel.Start();
        }

        // ---------- Submit handler ----------

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

            // Send to kernel via your communication layer.
            try
            {
                bool ok = _kernel.SendOperation(path, op);
                entry.Status = ok ? "Sent" : "Failed";
                AddLog($"[UI] {op} {path} -> {entry.Status}",
                    ok ? Brushes.LightGreen : Brushes.OrangeRed);
            }
            catch (Exception ex)
            {
                entry.Status = "Error";
                AddLog($"[UI] Exception: {ex.Message}", Brushes.OrangeRed);
            }

            // Refresh the row display because OperationEntry doesn't implement INPC here.
            // if you want the row to update without Refresh(), make OperationEntry implement INotifyPropertyChanged.
            OperationsList.Items.Refresh();

            PathTextBox.Clear();
            PathTextBox.Focus();
        }

        // ---------- Log handler (called from background thread) ---------

        // The kernel communication layer raises a LogReceived event for every log line.
        // The UI subscribes once in the constructor. Because the event probably fires on a background thread(kernel reader thread, named-pipe thread, etc.),
        // the handler wraps the actual UI update in Dispatcher.Invoke(...) — this is essential, otherwise you'll get cross-thread exceptions when modifying Logs.
        // Each log line is timestamped and color-coded based on keywords (error/fail - red, warn - yellow, shield/unshield - blue).
        // The list is capped at 5000 entries to keep memory bounded, and auto-scroll is honored if the checkbox is on.
        // OnClosed unsubscribes and stops the comm layer cleanly when the window closes.
        private void OnKernelLogReceived(object sender, string logLine)
        {
            // Marshal back to UI thread before touching the ObservableCollection.
            Dispatcher.Invoke(() => AddLog(logLine, ColorFor(logLine)));
        }

        private void AddLog(string text, Brush color)
        {
            Logs.Add(new LogEntry
            {
                Display = $"[{DateTime.Now:HH:mm:ss}] {text}",
                Color = color
            });

            // Cap log history to keep memory in check.
            const int maxLogs = 5000;
            while (Logs.Count > maxLogs) Logs.RemoveAt(0);

            if (AutoScrollCheckBox.IsChecked == true)
                LogScrollViewer.ScrollToEnd();
        }

        private static Brush ColorFor(string line)
        {
            if (string.IsNullOrEmpty(line)) return Brushes.LightGray;
            var lower = line.ToLowerInvariant();
            if (lower.Contains("error") || lower.Contains("fail"))
                return Brushes.OrangeRed;
            if (lower.Contains("warn"))
                return Brushes.Khaki;
            if (lower.Contains("shield") || lower.Contains("unshield"))
                return Brushes.LightSkyBlue;
            return Brushes.LightGray;
        }

        private void ClearLogsButton_Click(object sender, RoutedEventArgs e)
            => Logs.Clear();

        protected override void OnClosed(EventArgs e)
        {
            _kernel.LogReceived -= OnKernelLogReceived;
            _kernel.Stop();
            base.OnClosed(e);
        }
    }
}
