using mfuser.Models;
using mfuser.Services;
using Microsoft.Win32;
using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace mfuser;

public partial class TrustedProcessesWindow : Window
{
    private readonly IKernelComm _kernel;

    public ObservableCollection<TrustedProcessEntry> Entries { get; } = new();

    public TrustedProcessesWindow(IKernelComm kernel)
    {
        _kernel = kernel ?? throw new ArgumentNullException(nameof(kernel));
        InitializeComponent();

        foreach (TrustedProcessEntry entry in TrustedProcessStore.Load())
        {
            Entries.Add(entry);
        }

        RenumberEntries();
        EntriesList.ItemsSource = Entries;
    }

    private void AddButton_Click(object sender, RoutedEventArgs e) => AddCurrentInput();

    private void ImagePathTextBox_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) AddCurrentInput();
    }

    private void BrowseButton_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Select an executable to trust",
            Filter = "Executable files (*.exe)|*.exe|All files (*.*)|*.*",
            CheckFileExists = true,
        };

        if (dlg.ShowDialog(this) == true)
        {
            ImagePathTextBox.Text = dlg.FileName;
            AddCurrentInput();
        }
    }

    private void AddCurrentInput()
    {
        string? imagePath = ImagePathTextBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            MessageBox.Show(
                this,
                "Image path cannot be empty.",
                "Validation",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        // Refuse duplicates so we don't accumulate identical entries.
        foreach (TrustedProcessEntry existing in Entries)
        {
            if (string.Equals(existing.ImagePath, imagePath, StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show(
                    this,
                    "This image path is already in the trusted-process list.",
                    "Duplicate",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
                return;
            }
        }

        var entry = new TrustedProcessEntry
        {
            Index = Entries.Count + 1,
            ImagePath = imagePath,
            Status = "Sending...",
        };
        Entries.Add(entry);

        SendOperation(entry, TrustedProcessOperation.Add);

        ImagePathTextBox.Clear();
        ImagePathTextBox.Focus();
    }

    private void RemoveButton_Click(object sender, RoutedEventArgs e)
    {
        if (EntriesList.SelectedItem is TrustedProcessEntry entry)
        {
            RemoveEntry(entry);
        }
    }

    private void EntriesList_MouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (e.OriginalSource is not DependencyObject src) return;

        ListViewItem? row = FindAncestor<ListViewItem>(src);
        if (row?.DataContext is not TrustedProcessEntry entry) return;

        if (entry.Status == "Sending...")
        {
            // In-flight; ignore.
            return;
        }

        RemoveEntry(entry);
    }

    private void RemoveEntry(TrustedProcessEntry entry)
    {
        MessageBoxResult choice = MessageBox.Show(
            this,
            $"Remove this trusted process?\n\n{entry.ImagePath}",
            "Confirm",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (choice != MessageBoxResult.Yes) return;

        entry.Status = "Sending...";
        SendOperation(entry, TrustedProcessOperation.Remove);
    }

    /// <summary>
    /// Shared send path. Runs the kernel call on a background task so the UI
    /// stays responsive, then re-marshals to the UI thread to update the row
    /// and persist the list.
    /// </summary>
    private void SendOperation(TrustedProcessEntry entry, TrustedProcessOperation operation)
    {
        string imagePath = entry.ImagePath;

        _ = Task.Run(async () =>
        {
            bool ok = false;
            Exception? error = null;
            try
            {
                ok = await _kernel
                    .SendTrustedProcessOperationAsync(imagePath, operation, CancellationToken.None)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                error = ex;
            }

            await Dispatcher.InvokeAsync(() =>
            {
                if (error is not null)
                {
                    entry.Status = "Error";
                    MessageBox.Show(
                        this,
                        $"Trusted-process sync threw:\n\n{error.Message}",
                        "Send failed",
                        MessageBoxButton.OK,
                        MessageBoxImage.Error);
                }
                else
                {
                    entry.Status = ok ? "Sent" : "Failed";
                }

                if (operation == TrustedProcessOperation.Remove && ok)
                {
                    Entries.Remove(entry);
                    RenumberEntries();
                }

                // Persisting marks both the policy snapshot (operations.json
                // file protection) and the trusted-process snapshot
                // (trusted_processes_snapshot.bin) dirty. Kick the boot-file
                // write immediately so a reboot soon after the user's click
                // lands with the correct state rather than waiting for the
                // next 30s poll.
                TrustedProcessStore.Save(Entries);

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await TrustedProcessSnapshotService.UpdateAsync(CancellationToken.None)
                            .ConfigureAwait(false);
                    }
                    catch
                    {
                        // Best-effort; the periodic poll will retry.
                    }
                });
            });
        });
    }

    private void RenumberEntries()
    {
        for (int i = 0; i < Entries.Count; i++)
        {
            Entries[i].Index = i + 1;
        }
    }

    private static T? FindAncestor<T>(DependencyObject? current) where T : DependencyObject
    {
        while (current is not null)
        {
            if (current is T match) return match;
            current = VisualTreeHelper.GetParent(current);
        }
        return null;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
