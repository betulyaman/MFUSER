// Shared payload builders for messages exchanged between user-mode Agent and kernel-mode minifilter.
//
// IMPORTANT:
// - Payloads are strict binary layouts. Do not add extra bytes, padding, or trailing data.
// - All integers are little-endian.
// - All paths written to payload must be:
//   - NT path format (e.g. "\Device\HarddiskVolumeX\..."),
//   - lower-case,
//   - UTF-8 encoded,
//   - NUL-terminated,
//   - and length fields MUST include the NUL terminator.

using System.Buffers.Binary;
using System.Text;

public static class PayloadBuilders
{
    public readonly struct PayloadBuildResult
    {
        public PayloadBuildResult(ReadOnlyMemory<byte> payload, uint itemCount)
        {
            Payload = payload;
            ItemCount = itemCount;
        }

        public ReadOnlyMemory<byte> Payload { get; }
        public uint ItemCount { get; }
    }

    public readonly struct PolicySyncPayloadEntry
    {
        public PolicySyncPayloadEntry(MessageContract.PolicySyncStatus status, uint accessMask, string nativeNtPathLowercase)
        {
            Status = status;
            AccessMask = accessMask;
            NativeNtPathLowercase = nativeNtPathLowercase ?? throw new ArgumentNullException(nameof(nativeNtPathLowercase));
        }

        public MessageContract.PolicySyncStatus Status { get; }
        public uint AccessMask { get; }
        public string NativeNtPathLowercase { get; }
    }

    public readonly struct ConnectionContextPathAccessEntry
    {
        public ConnectionContextPathAccessEntry(string nativeNtPathLowercase, uint accessRights)
        {
            NativeNtPathLowercase = nativeNtPathLowercase ?? throw new ArgumentNullException(nameof(nativeNtPathLowercase));
            AccessRights = accessRights;
        }

        public string NativeNtPathLowercase { get; }
        public uint AccessRights { get; }
    }

    private static void WriteUInt32LittleEndian(byte[] destination, ref int offset, uint value)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(destination.AsSpan(offset, sizeof(uint)), value);
        offset += sizeof(uint);
    }

    private static void WriteUInt16LittleEndian(byte[] destination, ref int offset, ushort value)
    {
        BinaryPrimitives.WriteUInt16LittleEndian(destination.AsSpan(offset, sizeof(ushort)), value);
        offset += sizeof(ushort);
    }

    private static void WriteByte(byte[] destination, ref int offset, byte value)
    {
        destination[offset] = value;
        offset++;
    }

    private static void WriteUtf8StringBytesWithoutTerminator(byte[] destination, ref int offset, string value, int expectedUtf8ByteCount)
    {
        if (expectedUtf8ByteCount == 0)
        {
            return;
        }

        int written = Encoding.UTF8.GetBytes(value, 0, value.Length, destination, offset);
        offset += written;
    }

    /// <summary>
    /// Builds BLACKLIST payload bytes.
    ///
    /// Binary layout, repeated item count times:
    ///   [path_length_bytes: UInt32]              // UTF-8 bytes INCLUDING NUL terminator
    ///   [path_bytes: byte[path_length_bytes]]   // UTF-8 lower-case native Windows NT path INCLUDING trailing '\0'
    ///
    /// Guarantees:
    /// - NT path (converts DOS -> NT when needed)
    /// - lower-case
    /// - trailing NUL in payload
    /// - itemCount == number of paths written (kernel parse safe)
    /// </summary>
    public static PayloadBuildResult BlacklistPayloadBuilder(IReadOnlyCollection<string> dosPaths)
    {
        if (dosPaths is null)
        {
            throw new ArgumentNullException(nameof(dosPaths));
        }

        int count = dosPaths.Count;
        string[] nativeNtPathsLowercase = new string[count];
        int[] pathUtf8ByteCounts = new int[count];

        uint writtenItemCount = 0;
        int totalPayloadLengthBytes = 0;

        int index = 0;

        foreach (string dosPath in dosPaths)
        {
            if (string.IsNullOrWhiteSpace(dosPath))
            {
                throw new ArgumentException(
                    $"Blacklist DOS path collection contains a null/empty path at index {index}.",
                    nameof(dosPaths));
            }

            // Reject embedded NUL in input. Payload will add exactly one trailing terminator.
            if (dosPath.IndexOf('\0') >= 0)
            {
                throw new ArgumentException(
                    $"Blacklist DOS path contains embedded NUL at index {index}.",
                    nameof(dosPaths));
            }

            // DOS -> NT, and this method returns lower-case already.
            string ntPath = PathTranslator.DosPathToNtPath(dosPath);

            int pathUtf8ByteCount = Encoding.UTF8.GetByteCount(ntPath);

            if ((ulong)pathUtf8ByteCount + 1UL > uint.MaxValue)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(dosPaths),
                    $"Blacklist path is too long to encode with UInt32 length including NUL (index {index}).");
            }

            nativeNtPathsLowercase[index] = ntPath;
            pathUtf8ByteCounts[index] = pathUtf8ByteCount;

            checked
            {
                totalPayloadLengthBytes += sizeof(uint); // path_length_bytes
                totalPayloadLengthBytes += pathUtf8ByteCount; // path bytes
                totalPayloadLengthBytes += 1; // NUL
            }

            writtenItemCount++;
            index++;
        }

        var payload = new byte[totalPayloadLengthBytes];
        int offset = 0;

        for (int pathIndex = 0; pathIndex < count; pathIndex++)
        {
            string ntPath = nativeNtPathsLowercase[pathIndex];
            int pathUtf8ByteCount = pathUtf8ByteCounts[pathIndex];

            uint pathLengthBytesIncludingNullTerminator = checked((uint)pathUtf8ByteCount + 1u);

            // [path_length_bytes]
            WriteUInt32LittleEndian(payload, ref offset, pathLengthBytesIncludingNullTerminator);
            // [path_bytes (without terminator)]
            WriteUtf8StringBytesWithoutTerminator(payload, ref offset, ntPath, pathUtf8ByteCount);
            // [NUL terminator]
            WriteByte(payload, ref offset, 0);
        }

        return new PayloadBuildResult(payload, writtenItemCount);
    }

    /// <summary>
    /// Builds POLICY_SYNC payload bytes.
    ///
    /// Binary layout (little-endian), repeated item count times:
    ///   [status: UInt8]                // messageContract.PolicySyncStatus
    ///   [access_mask: UInt32]
    ///   [path_length_bytes: UInt32]    // UTF-8 bytes INCLUDING NUL terminator
    ///   [path_bytes: byte[path_length_bytes]]  // UTF-8 lower-case NT path INCLUDING trailing '\0'
    ///
    /// The returned itemCount equals the number of entries written.
    /// </summary>
    public static PayloadBuildResult BuildPolicySyncPayload(IReadOnlyList<PolicySyncPayloadEntry> policyEntries)
    {
        if (policyEntries is null)
        {
            throw new ArgumentNullException(nameof(policyEntries));
        }

        int count = policyEntries.Count;
        int[] pathUtf8ByteCounts = new int[count];

        int totalPayloadLengthBytes = 0;

        for (int index = 0; index < count; index++)
        {
            PolicySyncPayloadEntry policyEntry = policyEntries[index];

            if (string.IsNullOrWhiteSpace(policyEntry.NativeNtPathLowercase))
            {
                throw new ArgumentException(
                    "Policy entries collection contains a null/empty path.",
                    nameof(policyEntries));
            }

            int pathUtf8ByteCount = Encoding.UTF8.GetByteCount(policyEntry.NativeNtPathLowercase);
            pathUtf8ByteCounts[index] = pathUtf8ByteCount;

            checked
            {
                totalPayloadLengthBytes += sizeof(byte); // status
                totalPayloadLengthBytes += sizeof(uint); // access_mask
                totalPayloadLengthBytes += sizeof(uint); // path_length_bytes
                totalPayloadLengthBytes += pathUtf8ByteCount; // path bytes
                totalPayloadLengthBytes += 1; // NUL
            }
        }

        var payload = new byte[totalPayloadLengthBytes];
        int offset = 0;

        for (int index = 0; index < count; index++)
        {
            PolicySyncPayloadEntry policyEntry = policyEntries[index];
            int pathUtf8ByteCount = pathUtf8ByteCounts[index];

            // [status: UInt8]
            WriteByte(payload, ref offset, (byte)policyEntry.Status);
            // [access_mask: UInt32]
            WriteUInt32LittleEndian(payload, ref offset, policyEntry.AccessMask);
            // [path_length_bytes: UInt32]
            uint pathLengthBytesIncludingNullTerminator = checked((uint)pathUtf8ByteCount + 1u);
            WriteUInt32LittleEndian(payload, ref offset, pathLengthBytesIncludingNullTerminator);
            // [path_bytes (without terminator)]
            WriteUtf8StringBytesWithoutTerminator(payload, ref offset, policyEntry.NativeNtPathLowercase, pathUtf8ByteCount);
            // [NUL terminator]
            WriteByte(payload, ref offset, 0);
        }

        return new PayloadBuildResult(payload, itemCount: checked((uint)count));
    }

    /// <summary>
    /// Builds CONNECTION_CONTEXT payload bytes.
    ///
    /// Binary layout (little-endian):
    ///   [database_path_length: UInt16]         // UTF-8 bytes INCLUDING NUL terminator
    ///   [database_path_bytes: byte[...]]       // UTF-8 lower-case NT path INCLUDING trailing '\0'
    ///   [path_count: UInt32]
    ///   repeated path_count times:
    ///     [path_length: UInt16]                // UTF-8 bytes INCLUDING NUL terminator
    ///     [path_bytes: byte[...]]              // UTF-8 lower-case NT path INCLUDING trailing '\0'
    ///     [access_rights: UInt32]
    ///
    /// The returned itemCount equals path_count.
    /// </summary>
    public static PayloadBuildResult BuildConnectionContextPayload(
        string databaseNativeNtPathLowercase,
        IReadOnlyList<ConnectionContextPathAccessEntry> pathAccessEntries)
    {
        if (string.IsNullOrWhiteSpace(databaseNativeNtPathLowercase))
        {
            throw new ArgumentNullException(nameof(databaseNativeNtPathLowercase));
        }

        if (databaseNativeNtPathLowercase.IndexOf('\0') >= 0)
        {
            throw new ArgumentException("Database path contains embedded NUL.", nameof(databaseNativeNtPathLowercase));
        }

        if (pathAccessEntries is null)
        {
            throw new ArgumentNullException(nameof(pathAccessEntries));
        }

        // [database_path_length: UInt16] + [database_path_bytes] + [NUL]
        int databasePathUtf8ByteCount = Encoding.UTF8.GetByteCount(databaseNativeNtPathLowercase);

        if ((uint)databasePathUtf8ByteCount + 1u > ushort.MaxValue)
        {
            throw new InvalidOperationException("Database NT path is too long for UInt16 length field including NUL.");
        }

        int count = pathAccessEntries.Count;
        int[] pathUtf8ByteCounts = new int[count];
        int totalPayloadLengthBytes = 0;

        checked
        {
            totalPayloadLengthBytes += sizeof(ushort); // database_path_length
            totalPayloadLengthBytes += databasePathUtf8ByteCount; // database_path_bytes
            totalPayloadLengthBytes += 1; // NUL
            totalPayloadLengthBytes += sizeof(uint); // path_count
        }

        for (int index = 0; index < count; index++)
        {
            ConnectionContextPathAccessEntry entry = pathAccessEntries[index];

            if (string.IsNullOrWhiteSpace(entry.NativeNtPathLowercase))
            {
                throw new ArgumentException(
                    "Connection context entries collection contains a null/empty path.",
                    nameof(pathAccessEntries));
            }

            if (entry.NativeNtPathLowercase.IndexOf('\0') >= 0)
            {
                throw new ArgumentException(
                    "Connection context entry path contains embedded NUL.",
                    nameof(pathAccessEntries));
            }

            int pathUtf8ByteCount = Encoding.UTF8.GetByteCount(entry.NativeNtPathLowercase);

            if ((uint)pathUtf8ByteCount + 1u > ushort.MaxValue)
            {
                throw new InvalidOperationException("A connection context path is too long for UInt16 length field including NUL.");
            }

            pathUtf8ByteCounts[index] = pathUtf8ByteCount;

            checked
            {
                totalPayloadLengthBytes += sizeof(ushort); // path_length
                totalPayloadLengthBytes += pathUtf8ByteCount; // path_bytes
                totalPayloadLengthBytes += 1; // NUL
                totalPayloadLengthBytes += sizeof(uint); // access_rights
            }
        }

        var payload = new byte[totalPayloadLengthBytes];
        int offset = 0;

        // [database_path_length: UInt16]
        ushort databasePathLengthBytesIncludingNullTerminator = checked((ushort)(databasePathUtf8ByteCount + 1));
        WriteUInt16LittleEndian(payload, ref offset, databasePathLengthBytesIncludingNullTerminator);
        // [database_path_bytes (without terminator)]
        WriteUtf8StringBytesWithoutTerminator(payload, ref offset, databaseNativeNtPathLowercase, databasePathUtf8ByteCount);
        // [NUL terminator]
        WriteByte(payload, ref offset, 0);
        // [path_count: UInt32]
        uint pathCount = checked((uint)count);
        WriteUInt32LittleEndian(payload, ref offset, pathCount);

        // path entries in the database
        for (int index = 0; index < count; index++)
        {
            ConnectionContextPathAccessEntry entry = pathAccessEntries[index];
            int pathUtf8ByteCount = pathUtf8ByteCounts[index];

            // [path_length: UInt16]
            ushort pathLengthBytesIncludingNullTerminator = checked((ushort)(pathUtf8ByteCount + 1));
            WriteUInt16LittleEndian(payload, ref offset, pathLengthBytesIncludingNullTerminator);
            // [path_bytes (without terminator)]
            WriteUtf8StringBytesWithoutTerminator(payload, ref offset, entry.NativeNtPathLowercase, pathUtf8ByteCount);
            // [NUL terminator]
            WriteByte(payload, ref offset, 0);
            // [access_rights: UInt32]
            WriteUInt32LittleEndian(payload, ref offset, entry.AccessRights);
        }

        return new PayloadBuildResult(payload, itemCount: pathCount);
    }
}