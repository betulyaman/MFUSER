using System.Buffers;
using System.Runtime.InteropServices;

public static class PathTranslator
{
    /// <summary>
    /// Converts an NT-style device path (e.g., \Device\HarddiskVolumeX\...)
    /// to a DOS-style drive-letter path (e.g., C:\...).
    /// If the conversion fails, returns the original NT path.
    /// </summary>
    public static string? NtPathToDosPath(string? ntPath)
    {
        if (string.IsNullOrWhiteSpace(ntPath))
        {
            return ntPath;
        }

        const string devicePrefix = @"\Device\";

        if (!ntPath.StartsWith(devicePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return ntPath;
        }

        // Find end of "\Device\HarddiskVolumeX"
        int deviceNameEndIndex = ntPath.IndexOf('\\', devicePrefix.Length);

        if (deviceNameEndIndex < 0)
        {
            return ntPath;
        }

        ReadOnlySpan<char> deviceNameSpan = ntPath.AsSpan(0, deviceNameEndIndex);
        ReadOnlySpan<char> remainingPathSpan = ntPath.AsSpan(deviceNameEndIndex); // includes leading '\'

        string deviceName = new string(deviceNameSpan);

        char[] rentedBuffer = ArrayPool<char>.Shared.Rent(MessageContract.MaxNtPathLength);

        try
        {
            long result = FilterManagerNativeMethods.filter_get_dos_name(
                deviceName,
                rentedBuffer,
                (uint)rentedBuffer.Length);

            if (result != 0)
            {
                return ntPath;
            }

            int length = 0;

            while (length < rentedBuffer.Length && rentedBuffer[length] != '\0')
            {
                length++;
            }

            if (length == 0)
            {
                return ntPath;
            }

            string dosRoot = new string(rentedBuffer, 0, length);

            return string.Concat(dosRoot, remainingPathSpan);
        }
        finally
        {
            ArrayPool<char>.Shared.Return(rentedBuffer);
        }
    }

    /// <summary>
    /// Converts a DOS-style path (e.g., C:\folder\file.txt) to a lowercase NT device path
    /// (e.g., \Device\HarddiskVolumeX\folder\file.txt).
    /// </summary>
    public static string DosPathToNtPath(string dosPath)
    {
        if (string.IsNullOrWhiteSpace(dosPath))
        {
            throw new ArgumentException("Input path is null or empty.", nameof(dosPath));
        }

        string fullPath = Path.GetFullPath(dosPath);

        // Enforce/assume "C:\..." format.
        if (fullPath.Length < 3 || fullPath[1] != ':' || (fullPath[2] != '\\' && fullPath[2] != '/'))
        {
            throw new ArgumentException("Path must start with a drive root like X:\\", nameof(dosPath));
        }

        // "C:"
        string driveDesignator = fullPath.Substring(0, 2);

        char[] rentedBuffer = ArrayPool<char>.Shared.Rent(1024);

        try
        {
            int characterCount = FilterManagerNativeMethods.QueryDosDevice(driveDesignator, rentedBuffer, rentedBuffer.Length);

            if (characterCount == 0)
            {
                int error = Marshal.GetLastWin32Error();

                throw new InvalidOperationException($"QueryDosDevice failed for {driveDesignator}, error code {error}.");
            }

            // MULTI_SZ -> first string up to first '\0'
            int firstNullIndex = 0;

            while (firstNullIndex < rentedBuffer.Length && rentedBuffer[firstNullIndex] != '\0')
            {
                firstNullIndex++;
            }

            if (firstNullIndex == 0)
            {
                throw new InvalidOperationException($"QueryDosDevice returned an empty device mapping for {driveDesignator}.");
            }

            string devicePath = new string(rentedBuffer, 0, firstNullIndex);

            if (devicePath[0] != '\\')
            {
                devicePath = "\\" + devicePath;
            }

            // Relative part after "C:\"
            ReadOnlySpan<char> relativePathSpan = fullPath.AsSpan(3);

            // Normalize slashes only if needed (avoids unconditional Replace allocation).
            string normalizedRelativePath = NormalizeSlashesToBackslash(relativePathSpan);

            string finalPath = normalizedRelativePath.Length == 0
                ? devicePath
                : string.Concat(devicePath, "\\", normalizedRelativePath);

            return finalPath.ToLowerInvariant();
        }
        finally
        {
            ArrayPool<char>.Shared.Return(rentedBuffer);
        }
    }

    private static string NormalizeSlashesToBackslash(ReadOnlySpan<char> pathSpan)
    {
        int forwardSlashIndex = pathSpan.IndexOf('/');

        if (forwardSlashIndex < 0)
        {
            return new string(pathSpan);
        }

        return string.Create(pathSpan.Length, pathSpan, static (destination, source) =>
        {
            for (int index = 0; index < source.Length; index++)
            {
                char character = source[index];
                destination[index] = character == '/' ? '\\' : character;
            }
        });
    }
}
