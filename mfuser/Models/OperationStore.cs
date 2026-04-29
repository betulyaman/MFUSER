using System.IO;
using System.Text.Json;

namespace mfuser.Models
{
    /// <summary>
    /// Loads and saves the list of submitted operations as JSON in
    /// E:\workspace\mfuser\operations.json so the list survives
    /// application restarts.
    /// </summary>
    public static class OperationStore
    {
        private static readonly string FilePath = "E:\\workspace\\mfuser\\operations.json";

        private static readonly JsonSerializerOptions Options =
            new JsonSerializerOptions { WriteIndented = true };

        public static List<OperationEntry> Load()
        {
            try
            {
                if (!File.Exists(FilePath)) return new List<OperationEntry>();
                var json = File.ReadAllText(FilePath);
                return JsonSerializer.Deserialize<List<OperationEntry>>(json, Options)
                       ?? new List<OperationEntry>();
            }
            catch
            {
                // If the file is corrupt, just start empty rather than crash on launch.
                return new List<OperationEntry>();
            }
        }

        public static void Save(IEnumerable<OperationEntry> operations)
        {
            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(FilePath)!);
                var json = JsonSerializer.Serialize(operations, Options);
                File.WriteAllText(FilePath, json);
            }
            catch
            {
                // Saving must never crash the app on close. Swallow.
            }
        }
    }
}
