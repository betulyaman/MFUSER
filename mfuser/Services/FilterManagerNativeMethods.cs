using System.Runtime.InteropServices;

using MinifilterPortHandle = SafeFileHandle;

/// <summary>
/// Contains native method declarations for communication with the minifilter driver.
/// </summary>
public static class FilterManagerNativeMethods
{
    /// <summary>
    /// Used by the Filter Manager to match this reply to the original message (via MessageID),
    /// ensuring correct handling of concurrent requests.
    /// When the driver calls FltSendMessage(), the buffer received in user mode looks like:
    /// [FILTER_MESSAGE_HEADER][payload]
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct NativeFilterMessageHeader
    {
        /// <summary>
        /// The size (in bytes) of the reply buffer.
        /// </summary>
        public uint ReplyLength;

        /// <summary>
        /// On output from FilterGetMessage, this field receives the unique identifier (ID) for
        /// the message sent by the minifilter. If the application replies to the message, it
        /// must set this ID in the MessageId field of the FILTER_REPLY_HEADER header in the reply.
        /// </summary>
        public ulong MessageID;
    }

    /// <summary>
    /// Header for a reply sent from user mode to the minifilter driver via FilterReplyMessage.
    /// This header must mirror the layout expected by the Filter Manager.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public struct NativeFilterReplyHeader
    {
        /// <summary>
        /// NTSTATUS to return to the minifilter.
        /// </summary>
        public int NtStatus;

        /// <summary>
        /// Must be set to the FILTER_MESSAGE_HEADER.MessageID of the request being answered.
        /// </summary>
        public ulong MessageID;
    }

    private const string FltUserDll = "minifilter_communication_lib.dll";

    /// <summary>
    /// Connects to the filter communication port.
    /// </summary>
    [DllImport(FltUserDll, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern long filter_connect_communication_port(
        string portName,
        IntPtr context,
        uint contextSize,
        out MinifilterPortHandle portHandle);

    /// <summary>
    /// Sends a message to the minifilter.
    /// </summary>
    [DllImport(FltUserDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern long filter_send_message(
        MinifilterPortHandle port,
        IntPtr message,
        uint messageSize,
        IntPtr returnedMessage,
        uint returnedMessageSize);

    /// <summary>
    /// Receives a message from the minifilter.
    /// </summary>
    [DllImport(FltUserDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern long filter_get_message(
        MinifilterPortHandle port,
        IntPtr message,
        uint messageSize,
        IntPtr overlapped);

    /// <summary>
    /// Replies to a message from the minifilter.
    /// </summary>
    [DllImport(FltUserDll, CallingConvention = CallingConvention.Cdecl)]
    public static extern long filter_reply_message(
        MinifilterPortHandle port,
        IntPtr message,
        uint messageSize);

    /// <summary>
    ///  Gets the MS-DOS device name that corresponds to the given volume name.
    /// </summary>
    [DllImport(FltUserDll, CharSet = CharSet.Unicode, CallingConvention = CallingConvention.Cdecl)]
    public static extern long filter_get_dos_name(
        string volume,
        char[] dosPath,
        uint dosPathSize);

    /// <summary>
    /// Queries the DOS device path for a drive letter (e.g., D: → \Device\HarddiskVolumeX).
    /// </summary>
    [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true, CallingConvention = CallingConvention.StdCall)]
    public static extern int QueryDosDevice(
        string lpDeviceName,
        char[] lpTargetPath,
        int ucchMax);

    [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
    internal static extern bool GetOverlappedResult(
        SafeHandle hFile,
        IntPtr lpOverlapped,
        out uint lpNumberOfBytesTransferred,
        [MarshalAs(UnmanagedType.Bool)] bool bWait);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool ResetEvent(nint hEvent);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    internal static extern nint CreateEventA(
        IntPtr lpEventAttributes,
        bool bManualReset,
        bool bInitialState,
        string? lpName);
}