// Shared on-the-wire contracts between kernel-mode and user-mode.
// - Layout is binary-compatible with the C headers (Pack = 1).
// - Variable-length data (paths/messages) is NOT inside the structs; it follows them in the byte stream.
//
// IMPORTANT:
// - Do NOT change field order, sizes, or packing.
// - Do NOT replace these structs with classes.
// - When serializing/deserializing, validate lengths strictly to avoid out-of-bounds reads.

using System.Runtime.InteropServices;

public static class MessageContract
{
    public const uint MaxCiphertextBytes = 16u * 1024u; // 16 KiB
    public const uint MaxPayloadBytes = 64u * 1024u;
    // crypto_sign_BYTES + sizeof(PLAINTEXT_MESSAGE_HEADER) + MAX_PAYLOAD_BYTES
    public const uint MaxSignedBytes = NaclNativeMethods.crypto_sign_BYTES + 16 + MaxPayloadBytes;

    public const uint MaxItemCountInMessage = 512;
    public const uint GuardMessageMagic = 0x44525547u;
    public const int MaxNtPathLength = 512; // MUST equal MAX_NT_PATH_LENGTH_CHARS


    /// Defines access rights policies used for controlling file and directory access in the minifilter.
    [Flags]
    public enum AccessPolicy : uint
    {
        None = 0,
        Read = 1u << 0, // 0x00000001
        Write = 1u << 1, // 0x00000002
        Execute = 1u << 2, // 0x00000004
        Rename = 1u << 4,
        Move = 1u << 5,
        Delete = 1u << 3, // 0x00000008
        AllAccess = Read | Write | Execute | Delete, // 0x0000000F
        AllButDelete = AllAccess & ~Delete, // 0x00000007
        AllDeny = 0xFFFFFFFFu,
    }

    // kernel: typedef UINT8 PAYLOAD_TYPE;
    public enum PayloadType : byte
    {
        Invalid = 0,
        ConnectionContext = 1,
        PolicySync = 2,
        UnauthorizedFileOperation = 3,
        Log = 4,
        Blacklist = 5
    }

    // kernel: typedef UINT8 POLICY_SYNC_STATUS;
    public enum PolicySyncStatus : byte
    {
        None = 0,
        Add = 1,
        Remove = 2
    }

    // kernel: typedef UINT8 LOG_TYPE;
    public enum LogType : byte
    {
        None = 0,
        Info = 1,
        Warning = 2,
        Failure = 3
    }

    // kernel: typedef UCHAR MESSAGE_TYPE;
    public enum MessageType : byte
    {
        None = 0b0000,
        Plaintext = 0b0001,
        Signed = 0b0010,
        Encrypted = 0b0100,
        SignedEncrypted = 0b0111,
    }

    // File/stream operation types reported by the minifilter driver.
    // kernel: typedef UINT8 FILE_OPERATION_TYPE;
    public enum FileOperationType : byte
    {
        Invalid = 0,
        Create,
        Delete,
        FileOnClose,
        Move,
        Read,
        Rename,
        Write,
    };


    /* From user to kernel:

      POLICY_SYNC payload_bytes layout:
        repeated header.item_count times:
          [status: UINT8]
          [access_mask: UINT32]
          [path_length_bytes: UINT32]  // UTF-8 bytes, includes NUL terminator, lowercase NT path
          [path_bytes: UCHAR[path_length_bytes]]

    Connection Context Layout:
     [database_path_length: UINT16]   // UTF-8 bytes INCLUDING trailing '\0'
     [database_path_bytes: UCHAR[database_path_length]]
     [path_count: UINT32]                  // must equal header.item_count
     repeated path_count times:
       [path_length: UINT16]         // UTF-8 bytes INCLUDING trailing '\0'
       [path_bytes: UCHAR[path_length]]
       [access_rights: UINT32]

      BLACKLIST payload_bytes layout:
        repeated header.item_count times:
          [path_length_bytes: UINT32]  // UTF-8 bytes including NUL terminator
          [path_bytes: UCHAR[path_length_bytes]]
    */


    // ----- From kernel to user -----
    /*
      LOG payload_bytes layout:
        repeated header.item_count times:
          [log_type: UINT8]
          [time: UINT64]
          [message_length_bytes: UINT32]    // UTF-8 bytes; including NUL terminator
          [message_bytes: UCHAR[message_length_bytes]]
    */
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct LogEntry
    {
        public LogType LogType;
        public ulong Time;
        public uint MessageLengthBytes;

        // Followed by MessageLengthBytes bytes:
        // UTF-8 message including NUL terminator.
    }

    /*
      UNAUTHORIZED_FILE_OPERATION payload_bytes layout:
        repeated header.item_count times:
          [FILE_OPERATION_INFO]
    */
    [StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
    public struct UnauthorizedOperationInfo
    {
        /// The type of file operation being requested (create/delete/rename/move/read/write/…).
        public FileOperationType MinifilterOperationType;

        /// Source/subject path of the operation (the file/folder being acted upon).
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MaxNtPathLength)]
        public string FileName;

        /// Destination/target path for the operation, if applicable (e.g., rename/move).
        /// Empty or unspecified for operations that do not have a target.
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = MaxNtPathLength)]
        public string TargetName;

        public long EventTime; // LARGE_INTEGER
    }
    // -------------------------------


    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct EncryptedMessageHeader
    {
        public MessageType Type;

        // UCHAR nonce[crypto_box_NONCEBYTES];
        public fixed byte Nonce[NaclNativeMethods.crypto_box_NONCEBYTES];

        // UCHAR sender_encryption_public_key[crypto_box_PUBLICKEYBYTES];
        public fixed byte SenderEncryptionPublicKey[NaclNativeMethods.crypto_box_PUBLICKEYBYTES];

        public uint CiphertextSize;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public unsafe struct SignedMessageHeader
    {
        public MessageType Type;

        // UCHAR signer_public_key[crypto_sign_PUBLICKEYBYTES];
        public fixed byte SignerPublicKey[NaclNativeMethods.crypto_sign_PUBLICKEYBYTES];

        // bytes of (signature + recovered_plaintext)
        public uint SignedMessageSize;
    }

    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct PlaintextMessageHeader
    {
        // MESSAGE_TYPE_PLAINTEXT
        public MessageType Type;

        public uint Magic;
        public ushort HeaderSize;

        public PayloadType PayloadType;

        // number of bytes immediately following this header
        public uint PayloadLengthBytes;

        // number of entries in payload
        public uint ItemCount;
    }
}