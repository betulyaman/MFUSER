using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace mfuser.Models;

/// <summary>
/// One row in the upper-left "Submitted Operations" list.
/// Implements INotifyPropertyChanged so that updating
/// Status (or any other property) automatically refreshes the
/// row in the ListView — no manual Items.Refresh() call needed.
/// </summary>
public sealed class OperationEntry : INotifyPropertyChanged
{
    private int _index;
    private string _path = string.Empty;
    private string _operation = string.Empty;
    private string _status = string.Empty;

    public int Index
    {
        get => _index;
        set => SetField(ref _index, value);
    }

    public string Path
    {
        get => _path;
        set => SetField(ref _path, value ?? string.Empty);
    }

    public string Operation
    {
        get => _operation;
        set => SetField(ref _operation, value ?? string.Empty);
    }

    public string Status
    {
        get => _status;
        set => SetField(ref _status, value ?? string.Empty);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    // Helper that sets the backing field and raises PropertyChanged only if changed.
    private void SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}

/// <summary>
/// Severity level used to filter the log view.
/// </summary>
public enum LogLevel
{
    Info,
    Warning,
    Error,
}

/// <summary>
/// One row in the right-side log list.
/// Level drives filter buttons; Color drives the on-screen color.
/// </summary>
public sealed class LogEntry
{
    public string Display { get; init; } = string.Empty;
    public Brush Color { get; init; } = Brushes.LightGray;
    public LogLevel Level { get; init; }
}

/// <summary>
/// What the user picked in the log filter bar.
/// </summary>
public enum LogFilter
{
    All,
    Warnings,
    Errors,
}
