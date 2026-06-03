using System.ComponentModel;
using System.Runtime.CompilerServices;

namespace mfuser.Models;

/// <summary>
/// One row in the Trusted Processes management dialog.
///
/// "Trusted" means the agent has Authenticode-verified this image path
/// (or the user has explicitly opted in) and the kernel will grant trusted
/// callers the upper half of the per-file rights bitmask when this binary
/// initiates an IRP against a shielded file.
/// </summary>
public sealed class TrustedProcessEntry : INotifyPropertyChanged
{
    private int _index;
    private string _imagePath = string.Empty;
    private string _status = string.Empty;

    /// 1-based row number for display.
    public int Index
    {
        get => _index;
        set => SetField(ref _index, value);
    }

    /// DOS-style image path the user entered or browsed to.
    public string ImagePath
    {
        get => _imagePath;
        set => SetField(ref _imagePath, value ?? string.Empty);
    }

    /// Last sync result ("Sent", "Failed", "Error", or "Sending...").
    public string Status
    {
        get => _status;
        set => SetField(ref _status, value ?? string.Empty);
    }

    public event PropertyChangedEventHandler? PropertyChanged;

    private void SetField<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return;
        field = value;
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
    }
}
