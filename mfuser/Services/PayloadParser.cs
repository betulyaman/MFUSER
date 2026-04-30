using System.Collections.ObjectModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;

namespace mfuser.Services;

public static class PayloadParser
{
    public readonly struct ParsedLogEntry
    {
        public MessageContract.LogType LogType { get; init; }
        public ulong Time { get; init; }
        public uint MessageLengthBytes { get; init; }
        public string Message { get; init; }
    }

    private static readonly int LogEntryHeaderSize = Unsafe.SizeOf<MessageContract.LogEntry>();

    private static readonly ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> EmptyUnauthorizedOperations =
        Array.AsReadOnly(Array.Empty<MessageContract.UnauthorizedOperationInfo>());

    private static readonly ReadOnlyCollection<ParsedLogEntry> EmptyParsedLogEntries =
        Array.AsReadOnly(Array.Empty<ParsedLogEntry>());

    public static bool ParsePayload(
        in MessageContract.PlaintextMessageHeader plaintextMessageHeader,
        ReadOnlySpan<byte> payloadBytes,
        out ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> unauthorizedOperations,
        out ReadOnlyCollection<ParsedLogEntry> parsedLogEntries)
    {
        unauthorizedOperations = EmptyUnauthorizedOperations;
        parsedLogEntries = EmptyParsedLogEntries;

        if (plaintextMessageHeader.PayloadLengthBytes != (uint)payloadBytes.Length)
        {
            return false;
        }

        if (payloadBytes.IsEmpty)
        {
            return plaintextMessageHeader.ItemCount == 0;
        }

        if (plaintextMessageHeader.ItemCount == 0)
        {
            return false;
        }

        return plaintextMessageHeader.PayloadType switch
        {
            MessageContract.PayloadType.UnauthorizedFileOperation =>
                ParseUnauthorizedOperations(
                    in plaintextMessageHeader,
                    payloadBytes,
                    out unauthorizedOperations),

            MessageContract.PayloadType.Log =>
                ParseLogEntries(
                    in plaintextMessageHeader,
                    payloadBytes,
                    out parsedLogEntries),

            _ => false
        };
    }

    private static bool ParseUnauthorizedOperations(
        in MessageContract.PlaintextMessageHeader plaintextMessageHeader,
        ReadOnlySpan<byte> payloadBytes,
        out ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> unauthorizedOperations)
    {
        unauthorizedOperations = EmptyUnauthorizedOperations;

        if (plaintextMessageHeader.PayloadType != MessageContract.PayloadType.UnauthorizedFileOperation)
        {
            return false;
        }

        const int operationTypeSize = sizeof(byte);
        const int eventTimeSize = sizeof(long);

        int fileNameSize = checked(MessageContract.MaxNtPathLength * sizeof(char));
        int targetNameSize = checked(MessageContract.MaxNtPathLength * sizeof(char));
        int entrySize = checked(operationTypeSize + fileNameSize + targetNameSize + eventTimeSize);

        ulong expectedPayloadLength = (ulong)entrySize * plaintextMessageHeader.ItemCount;

        if ((ulong)payloadBytes.Length != expectedPayloadLength)
        {
            return false;
        }

        var parsedUnauthorizedOperations = new MessageContract.UnauthorizedOperationInfo[plaintextMessageHeader.ItemCount];

        int offset = 0;

        for (int index = 0; index < parsedUnauthorizedOperations.Length; index++)
        {
            if (offset > payloadBytes.Length - entrySize)
            {
                return false;
            }

            ReadOnlySpan<byte> entryBytes = payloadBytes.Slice(offset, entrySize);

            byte operationTypeRaw = entryBytes[0];

            if (operationTypeRaw == (byte)MessageContract.FileOperationType.Invalid ||
                operationTypeRaw > (byte)MessageContract.FileOperationType.Write)
            {
                return false;
            }

            MessageContract.FileOperationType operationType =
                (MessageContract.FileOperationType)operationTypeRaw;

            ReadOnlySpan<byte> fileNameBytes =
                entryBytes.Slice(operationTypeSize, fileNameSize);

            ReadOnlySpan<byte> targetNameBytes =
                entryBytes.Slice(operationTypeSize + fileNameSize, targetNameSize);

            ReadOnlySpan<byte> eventTimeBytes =
                entryBytes.Slice(operationTypeSize + fileNameSize + targetNameSize, eventTimeSize);

            string fileNameNtPath = DecodeFixedUtf16String(fileNameBytes);
            string targetNameNtPath = DecodeFixedUtf16String(targetNameBytes);

            if (string.IsNullOrWhiteSpace(fileNameNtPath))
            {
                return false;
            }

            if ((operationType == MessageContract.FileOperationType.Move ||
                 operationType == MessageContract.FileOperationType.Rename) &&
                string.IsNullOrWhiteSpace(targetNameNtPath))
            {
                return false;
            }

            long eventTime = MemoryMarshal.Read<long>(eventTimeBytes);

            string normalizedFileName =
                PathTranslator.NtPathToDosPath(fileNameNtPath) ?? fileNameNtPath;

            string normalizedTargetName =
                PathTranslator.NtPathToDosPath(targetNameNtPath) ?? targetNameNtPath;

            parsedUnauthorizedOperations[index] = new MessageContract.UnauthorizedOperationInfo
            {
                MinifilterOperationType = operationType,
                FileName = normalizedFileName,
                TargetName = normalizedTargetName,
                EventTime = eventTime
            };

            offset += entrySize;
        }

        if (offset != payloadBytes.Length)
        {
            return false;
        }

        unauthorizedOperations = Array.AsReadOnly(parsedUnauthorizedOperations);

        return true;
    }

    private static bool ParseLogEntries(
        in MessageContract.PlaintextMessageHeader plaintextMessageHeader,
        ReadOnlySpan<byte> payloadBytes,
        out ReadOnlyCollection<ParsedLogEntry> parsedLogEntries)
    {
        parsedLogEntries = EmptyParsedLogEntries;

        if (plaintextMessageHeader.PayloadType != MessageContract.PayloadType.Log)
        {
            return false;
        }

        var parsedEntries = new ParsedLogEntry[plaintextMessageHeader.ItemCount];
        int offset = 0;

        for (int index = 0; index < parsedEntries.Length; index++)
        {
            int remainingLength = payloadBytes.Length - offset;

            if (remainingLength < LogEntryHeaderSize)
            {
                return false;
            }

            MessageContract.LogEntry logEntryHeader =
                MemoryMarshal.Read<MessageContract.LogEntry>(
                    payloadBytes.Slice(offset, LogEntryHeaderSize));

            if (logEntryHeader.LogType < MessageContract.LogType.Info ||
                logEntryHeader.LogType > MessageContract.LogType.Failure)
            {
                return false;
            }

            if (logEntryHeader.MessageLengthBytes == 0 ||
                logEntryHeader.MessageLengthBytes > MessageContract.MaxPayloadBytes)
            {
                return false;
            }

            if (logEntryHeader.MessageLengthBytes > (uint)(remainingLength - LogEntryHeaderSize))
            {
                return false;
            }

            int messageLengthBytes;

            try
            {
                messageLengthBytes = checked((int)logEntryHeader.MessageLengthBytes);
            }
            catch (OverflowException)
            {
                return false;
            }

            ReadOnlySpan<byte> messageBytes =
                payloadBytes.Slice(offset + LogEntryHeaderSize, messageLengthBytes);

            if (messageBytes[^1] != 0)
            {
                return false;
            }

            // Zero-terminated UTF-8 string; strip the trailing NUL.
            string message = Encoding.UTF8.GetString(messageBytes[..^1]);

            parsedEntries[index] = new ParsedLogEntry
            {
                LogType = logEntryHeader.LogType,
                Time = logEntryHeader.Time,
                MessageLengthBytes = logEntryHeader.MessageLengthBytes,
                Message = message
            };

            offset += LogEntryHeaderSize + messageLengthBytes;
        }

        if (offset != payloadBytes.Length)
        {
            return false;
        }

        parsedLogEntries = Array.AsReadOnly(parsedEntries);

        return true;
    }

    private static string DecodeFixedUtf16String(ReadOnlySpan<byte> bytes)
    {
        ReadOnlySpan<char> characters = MemoryMarshal.Cast<byte, char>(bytes);

        int zeroTerminatorIndex = characters.IndexOf('\0');

        if (zeroTerminatorIndex >= 0)
        {
            characters = characters.Slice(0, zeroTerminatorIndex);
        }

        return new string(characters);
    }
}