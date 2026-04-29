using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows.Media;

namespace mfuser.Models
{
    /// <summary>
    /// One row in the upper-left "Submitted Operations" list.
    /// Implements INotifyPropertyChanged so that updating Status (or any other
    /// property) automatically refreshes the row in the ListView - no manual
    /// Items.Refresh() needed.
    /// </summary>
    public class OperationEntry : INotifyPropertyChanged
    {
        private int _index;
        private string _path;
        private string _operation;
        private string _status;

        public int Index
        {
            get => _index;
            set => SetField(ref _index, value);
        }

        public string Path
        {
            get => _path;
            set => SetField(ref _path, value);
        }

        public string Operation
        {
            get => _operation;
            set => SetField(ref _operation, value);
        }

        public string Status
        {
            get => _status;
            set => SetField(ref _status, value);
        }

        public event PropertyChangedEventHandler PropertyChanged;

        // Helper that sets the backing field and raises PropertyChanged only if changed.
        private void SetField<T>(ref T field, T value, [CallerMemberName] string name = null)
        {
            if (Equals(field, value)) return;
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
        Error
    }

    /// <summary>
    /// One row in the right-side log list.
    /// Level is used by the filter buttons; Color drives the on-screen color.
    /// </summary>
    public class LogEntry
    {
        public string Display { get; set; }
        public Brush Color { get; set; }
        public LogLevel Level { get; set; }
    }

    /// <summary>
    /// What the user picked in the log filter bar.
    /// </summary>
    public enum LogFilter
    {
        All,
        Warnings,
        Errors
    }
}
