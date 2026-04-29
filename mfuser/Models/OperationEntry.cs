using System.Windows.Media;

namespace mfuser.Models
{
    /// <summary>
    /// One row in the upper-left "Submitted Operations" list.
    /// </summary>
    public class OperationEntry
    {
        public int Index { get; set; }
        public string Path { get; set; }
        public string Operation { get; set; }   // "shield" or "unshield"
        public string Status { get; set; }      // "Sending...", "Sent", "Failed", "Error"
    }

    /// <summary>
    /// One row in the right-side log list.
    /// </summary>
    public class LogEntry
    {
        public string Display { get; set; }
        public Brush Color { get; set; }
    }
}
