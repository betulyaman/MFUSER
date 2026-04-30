using System.Buffers;
using System.Collections.ObjectModel;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace mfuser.Services;

public static class MessageDecoder
{
    private static readonly int EncryptedMessageHeaderSize = Unsafe.SizeOf<MessageContract.EncryptedMessageHeader>();
    private static readonly int SignedMessageHeaderSize = Unsafe.SizeOf<MessageContract.SignedMessageHeader>();
    private static readonly int PlaintextMessageHeaderSize = Unsafe.SizeOf<MessageContract.PlaintextMessageHeader>();

    private static readonly ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> EmptyUnauthorizedOperations =
        Array.AsReadOnly(Array.Empty<MessageContract.UnauthorizedOperationInfo>());

    private static readonly ReadOnlyCollection<PayloadParser.ParsedLogEntry> EmptyLogEntries =
        Array.AsReadOnly(Array.Empty<PayloadParser.ParsedLogEntry>());

    /// <summary>
    /// Decodes and validates a minifilter message container.
    ///
    /// The message may be:
    ///   - Plaintext
    ///   - Signed
    ///   - Encrypted
    ///   - SignedEncrypted
    ///
    /// The function performs:
    ///   - container validation
    ///   - optional decryption
    ///   - optional signature verification
    ///   - plaintext validation
    ///   - payload parsing
    ///
    /// On success it returns parsed payload objects.
    ///
    /// Encrypted message format:
    ///  [ENCRYPTED_MESSAGE_HEADER][ciphertext...]
    ///      plaintext after crypto_box_open():
    ///      [SIGNED_MESSAGE_HEADER][signed_message bytes]
    ///          signed_message = signature(crypto_sign_BYTES) + recovered_plaintext
    ///
    /// Signed message format:
    ///  [SIGNED_MESSAGE_HEADER][signed_message bytes]
    ///      signed_message = signature(crypto_sign_BYTES) + recovered_plaintext
    ///
    /// Recovered plaintext format:
    ///  [PLAINTEXT_MESSAGE_HEADER]
    ///  [payload_bytes ... payload_length]
    ///
    /// No extra trailing bytes are allowed (strict length validation).
    /// </summary>
    public static bool DecodeAndParseMessage(
        ReadOnlySpan<byte> messageBytes,
        out ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> unauthorizedOperations,
        out ReadOnlyCollection<PayloadParser.ParsedLogEntry> logEntries)
    {
        unauthorizedOperations = EmptyUnauthorizedOperations;
        logEntries = EmptyLogEntries;

        if (messageBytes.Length < 1)
        {
            return false;
        }

        MessageContract.MessageType outerMessageType = (MessageContract.MessageType)messageBytes[0];

        return outerMessageType switch
        {
            MessageContract.MessageType.Plaintext => ParsePlaintext(
                messageBytes,
                out unauthorizedOperations,
                out logEntries),

            MessageContract.MessageType.Signed => ParseSignedContainerToPlaintext(
                messageBytes,
                out unauthorizedOperations,
                out logEntries),

            MessageContract.MessageType.Encrypted => ParseEncryptedContainer(
                messageBytes,
                expectedEncryptedType: MessageContract.MessageType.Encrypted,
                out unauthorizedOperations,
                out logEntries),

            MessageContract.MessageType.SignedEncrypted => ParseEncryptedContainer(
                messageBytes,
                expectedEncryptedType: MessageContract.MessageType.SignedEncrypted,
                out unauthorizedOperations,
                out logEntries),

            _ => false
        };
    }

    private static bool ParseEncryptedContainerAndGetCiphertext(
        ReadOnlySpan<byte> encryptedContainerBytes,
        out MessageContract.EncryptedMessageHeader encryptedMessageHeader,
        out ReadOnlySpan<byte> ciphertextBytes)
    {
        encryptedMessageHeader = default;
        ciphertextBytes = default;

        if (encryptedContainerBytes.Length < EncryptedMessageHeaderSize)
        {
            return false;
        }

        encryptedMessageHeader = MemoryMarshal.Read<MessageContract.EncryptedMessageHeader>(
            encryptedContainerBytes.Slice(0, EncryptedMessageHeaderSize));

        if (!ValidateEncryptedHeader(in encryptedMessageHeader))
        {
            return false;
        }

        int ciphertextLength;
        int expectedContainerLength;

        try
        {
            ciphertextLength = checked((int)encryptedMessageHeader.CiphertextSize);
            expectedContainerLength = checked(EncryptedMessageHeaderSize + ciphertextLength);
        }
        catch (OverflowException)
        {
            return false;
        }

        if (expectedContainerLength != encryptedContainerBytes.Length)
        {
            return false;
        }

        ciphertextBytes = encryptedContainerBytes.Slice(EncryptedMessageHeaderSize, ciphertextLength);

        return true;
    }

    private static bool ValidateEncryptedHeader(in MessageContract.EncryptedMessageHeader encryptedMessageHeader)
    {
        if (encryptedMessageHeader.Type != MessageContract.MessageType.Encrypted &&
            encryptedMessageHeader.Type != MessageContract.MessageType.SignedEncrypted)
        {
            return false;
        }

        if (encryptedMessageHeader.CiphertextSize == 0 ||
            encryptedMessageHeader.CiphertextSize > MessageContract.MaxCiphertextBytes)
        {
            return false;
        }

        if (encryptedMessageHeader.CiphertextSize <= NaclNativeMethods.crypto_box_ZEROBYTES)
        {
            return false;
        }

        return true;
    }

    private static bool DecryptCiphertext(
        ReadOnlySpan<byte> ciphertextBytes,
        in MessageContract.EncryptedMessageHeader encryptedMessageHeader,
        ReadOnlySpan<byte> receiverSecretKeyBytes,
        byte[] decryptedBuffer,
        out int decryptedPlaintextLength)
    {
        decryptedPlaintextLength = 0;

        if (ciphertextBytes.IsEmpty)
        {
            return false;
        }

        if (receiverSecretKeyBytes.Length != NaclNativeMethods.crypto_box_SECRETKEYBYTES)
        {
            return false;
        }

        if (decryptedBuffer.Length < ciphertextBytes.Length)
        {
            return false;
        }

        if ((uint)ciphertextBytes.Length != encryptedMessageHeader.CiphertextSize)
        {
            return false;
        }

        if (ciphertextBytes.Length <= NaclNativeMethods.crypto_box_ZEROBYTES)
        {
            return false;
        }

        if (ciphertextBytes.Length < NaclNativeMethods.crypto_box_BOXZEROBYTES)
        {
            return false;
        }

        for (int index = 0; index < NaclNativeMethods.crypto_box_BOXZEROBYTES; index++)
        {
            if (ciphertextBytes[index] != 0)
            {
                return false;
            }
        }

        int cryptoResult;

        unsafe
        {
            fixed (byte* decryptedBufferPointer = decryptedBuffer)
            fixed (byte* ciphertextPointer = ciphertextBytes)
            fixed (byte* receiverSecretKeyPointer = receiverSecretKeyBytes)
            fixed (MessageContract.EncryptedMessageHeader* encryptedMessageHeaderPointer = &encryptedMessageHeader)
            {
                cryptoResult = NaclNativeMethods.crypto_box_curve25519xsalsa20poly1305_tweet_open(
                    (IntPtr)decryptedBufferPointer,
                    (IntPtr)ciphertextPointer,
                    checked((ulong)ciphertextBytes.Length),
                    (IntPtr)encryptedMessageHeaderPointer->Nonce,
                    (IntPtr)encryptedMessageHeaderPointer->SenderEncryptionPublicKey,
                    (IntPtr)receiverSecretKeyPointer);
            }
        }

        if (cryptoResult != 0)
        {
            return false;
        }

        int recoveredPlaintextLength = ciphertextBytes.Length - NaclNativeMethods.crypto_box_ZEROBYTES;

        // Shift the recovered plaintext left over the leading ZERO_BYTES region.
        // Span.CopyTo handles this overlapping-buffer case correctly.
        decryptedBuffer.AsSpan(
            NaclNativeMethods.crypto_box_ZEROBYTES,
            recoveredPlaintextLength).CopyTo(decryptedBuffer);

        decryptedPlaintextLength = recoveredPlaintextLength;

        return true;
    }

    private static bool ValidateSignedHeader(in MessageContract.SignedMessageHeader signedMessageHeader)
    {
        if (signedMessageHeader.Type != MessageContract.MessageType.Signed)
        {
            return false;
        }

        uint minimumSignedMessageSize;

        try
        {
            minimumSignedMessageSize = checked(
                (uint)NaclNativeMethods.crypto_sign_BYTES + (uint)PlaintextMessageHeaderSize);
        }
        catch (OverflowException)
        {
            return false;
        }

        if (signedMessageHeader.SignedMessageSize < minimumSignedMessageSize)
        {
            return false;
        }

        if (signedMessageHeader.SignedMessageSize > MessageContract.MaxSignedBytes)
        {
            return false;
        }

        return true;
    }

    private static bool GetSignedMessageBytes(
        ReadOnlySpan<byte> signedContainerBytes,
        in MessageContract.SignedMessageHeader signedMessageHeader,
        out ReadOnlySpan<byte> signedMessageBytes)
    {
        signedMessageBytes = default;

        int signedMessageLength;
        int expectedContainerLength;

        try
        {
            signedMessageLength = checked((int)signedMessageHeader.SignedMessageSize);
            expectedContainerLength = checked(SignedMessageHeaderSize + signedMessageLength);
        }
        catch (OverflowException)
        {
            return false;
        }

        if (expectedContainerLength != signedContainerBytes.Length)
        {
            return false;
        }

        signedMessageBytes = signedContainerBytes.Slice(SignedMessageHeaderSize, signedMessageLength);

        return true;
    }

    private static bool VerifySignedMessage(
        in MessageContract.SignedMessageHeader signedMessageHeader,
        ReadOnlySpan<byte> signedMessageBytes,
        byte[] verifiedPlaintextBuffer,
        int maximumVerifiedPlaintextLength,
        out int verifiedPlaintextLength)
    {
        verifiedPlaintextLength = 0;

        if ((uint)signedMessageBytes.Length != signedMessageHeader.SignedMessageSize)
        {
            return false;
        }

        if (maximumVerifiedPlaintextLength < PlaintextMessageHeaderSize)
        {
            return false;
        }

        if (verifiedPlaintextBuffer.Length < maximumVerifiedPlaintextLength)
        {
            return false;
        }

        int cryptoResult;
        ulong verifiedPlaintextLengthUnsigned;

        unsafe
        {
            fixed (byte* verifiedPlaintextPointer = verifiedPlaintextBuffer)
            fixed (byte* signedMessagePointer = signedMessageBytes)
            fixed (MessageContract.SignedMessageHeader* signedMessageHeaderPointer = &signedMessageHeader)
            {
                cryptoResult = NaclNativeMethods.crypto_sign_ed25519_tweet_open(
                    (IntPtr)verifiedPlaintextPointer,
                    out verifiedPlaintextLengthUnsigned,
                    (IntPtr)signedMessagePointer,
                    checked((ulong)signedMessageBytes.Length),
                    (IntPtr)signedMessageHeaderPointer->SignerPublicKey);
            }
        }

        if (cryptoResult != 0)
        {
            return false;
        }

        if (verifiedPlaintextLengthUnsigned > (ulong)maximumVerifiedPlaintextLength)
        {
            return false;
        }

        verifiedPlaintextLength = (int)verifiedPlaintextLengthUnsigned;

        return true;
    }

    private static bool ValidatePlaintextHeader(
        in MessageContract.PlaintextMessageHeader plaintextMessageHeader,
        uint plaintextContainerLength)
    {
        if (plaintextMessageHeader.Type != MessageContract.MessageType.Plaintext)
        {
            return false;
        }

        if (plaintextMessageHeader.Magic != MessageContract.GuardMessageMagic)
        {
            return false;
        }

        if (plaintextMessageHeader.HeaderSize != PlaintextMessageHeaderSize)
        {
            return false;
        }

        if (plaintextMessageHeader.PayloadType != MessageContract.PayloadType.UnauthorizedFileOperation &&
            plaintextMessageHeader.PayloadType != MessageContract.PayloadType.Log)
        {
            return false;
        }

        if (plaintextMessageHeader.PayloadLengthBytes > MessageContract.MaxPayloadBytes)
        {
            return false;
        }

        if (plaintextMessageHeader.ItemCount > MessageContract.MaxItemCountInMessage)
        {
            return false;
        }

        uint expectedContainerLength;

        try
        {
            expectedContainerLength = checked((uint)plaintextMessageHeader.HeaderSize + plaintextMessageHeader.PayloadLengthBytes);
        }
        catch (OverflowException)
        {
            return false;
        }

        if (expectedContainerLength != plaintextContainerLength)
        {
            return false;
        }

        if (plaintextMessageHeader.PayloadLengthBytes == 0 && plaintextMessageHeader.ItemCount != 0)
        {
            return false;
        }

        return true;
    }

    private static bool ParsePlaintext(
        ReadOnlySpan<byte> plaintextContainerBytes,
        out ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> unauthorizedOperations,
        out ReadOnlyCollection<PayloadParser.ParsedLogEntry> logEntries)
    {
        unauthorizedOperations = EmptyUnauthorizedOperations;
        logEntries = EmptyLogEntries;

        if (plaintextContainerBytes.Length < PlaintextMessageHeaderSize)
        {
            return false;
        }

        MessageContract.PlaintextMessageHeader plaintextMessageHeader =
            MemoryMarshal.Read<MessageContract.PlaintextMessageHeader>(
                plaintextContainerBytes.Slice(0, PlaintextMessageHeaderSize));

        uint plaintextContainerLength;

        try
        {
            plaintextContainerLength = checked((uint)plaintextContainerBytes.Length);
        }
        catch (OverflowException)
        {
            return false;
        }

        if (!ValidatePlaintextHeader(in plaintextMessageHeader, plaintextContainerLength))
        {
            return false;
        }

        int payloadLength;

        try
        {
            payloadLength = checked((int)plaintextMessageHeader.PayloadLengthBytes);
        }
        catch (OverflowException)
        {
            return false;
        }

        ReadOnlySpan<byte> payloadBytes = plaintextContainerBytes.Slice(PlaintextMessageHeaderSize, payloadLength);

        return PayloadParser.ParsePayload(
            in plaintextMessageHeader,
            payloadBytes,
            out unauthorizedOperations,
            out logEntries);
    }

    private static bool ParseSignedContainerToPlaintext(
        ReadOnlySpan<byte> signedContainerBytes,
        out ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> unauthorizedOperations,
        out ReadOnlyCollection<PayloadParser.ParsedLogEntry> logEntries)
    {
        unauthorizedOperations = EmptyUnauthorizedOperations;
        logEntries = EmptyLogEntries;

        if (signedContainerBytes.Length < SignedMessageHeaderSize)
        {
            return false;
        }

        MessageContract.SignedMessageHeader signedMessageHeader =
            MemoryMarshal.Read<MessageContract.SignedMessageHeader>(
                signedContainerBytes.Slice(0, SignedMessageHeaderSize));

        if (!ValidateSignedHeader(in signedMessageHeader))
        {
            return false;
        }

        if (!GetSignedMessageBytes(
                signedContainerBytes,
                in signedMessageHeader,
                out ReadOnlySpan<byte> signedMessageBytes))
        {
            return false;
        }

        int maximumVerifiedPlaintextLength;

        try
        {
            maximumVerifiedPlaintextLength = checked((int)signedMessageHeader.SignedMessageSize - NaclNativeMethods.crypto_sign_BYTES);
        }
        catch (OverflowException)
        {
            return false;
        }

        if (maximumVerifiedPlaintextLength < PlaintextMessageHeaderSize)
        {
            return false;
        }

        byte[] verifiedPlaintextBuffer = ArrayPool<byte>.Shared.Rent(maximumVerifiedPlaintextLength);

        try
        {
            if (!VerifySignedMessage(
                    in signedMessageHeader,
                    signedMessageBytes,
                    verifiedPlaintextBuffer,
                    maximumVerifiedPlaintextLength,
                    out int verifiedPlaintextLength))
            {
                return false;
            }

            ReadOnlySpan<byte> plaintextBytes = new ReadOnlySpan<byte>(verifiedPlaintextBuffer, 0, verifiedPlaintextLength);

            return ParsePlaintext(
                plaintextBytes,
                out unauthorizedOperations,
                out logEntries);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(verifiedPlaintextBuffer, clearArray: true);
        }
    }

    private static bool ParseEncryptedContainer(
        ReadOnlySpan<byte> encryptedContainerBytes,
        MessageContract.MessageType expectedEncryptedType,
        out ReadOnlyCollection<MessageContract.UnauthorizedOperationInfo> unauthorizedOperations,
        out ReadOnlyCollection<PayloadParser.ParsedLogEntry> logEntries)
    {
        unauthorizedOperations = EmptyUnauthorizedOperations;
        logEntries = EmptyLogEntries;

        if (!ParseEncryptedContainerAndGetCiphertext(
                encryptedContainerBytes,
                out MessageContract.EncryptedMessageHeader encryptedMessageHeader,
                out ReadOnlySpan<byte> ciphertextBytes))
        {
            return false;
        }

        if (encryptedMessageHeader.Type != expectedEncryptedType)
        {
            return false;
        }

        byte[] decryptedBuffer = ArrayPool<byte>.Shared.Rent(ciphertextBytes.Length);
        byte[] userEncryptionSecretKey = CryptoMaterialProvider.GetUserEncryptionSecretKey();

        try
        {
            if (!DecryptCiphertext(
                    ciphertextBytes,
                    in encryptedMessageHeader,
                    userEncryptionSecretKey.AsSpan(),
                    decryptedBuffer,
                    out int decryptedContentLength))
            {
                CryptoMaterialProvider.ClearKeyMaterial(userEncryptionSecretKey);

                return false;
            }

            CryptoMaterialProvider.ClearKeyMaterial(userEncryptionSecretKey);

            if (expectedEncryptedType == MessageContract.MessageType.Encrypted)
            {
                if (decryptedContentLength < PlaintextMessageHeaderSize)
                {
                    return false;
                }

                ReadOnlySpan<byte> plaintextBytes = new ReadOnlySpan<byte>(decryptedBuffer, 0, decryptedContentLength);

                return ParsePlaintext(
                    plaintextBytes,
                    out unauthorizedOperations,
                    out logEntries);
            }

            if (decryptedContentLength < SignedMessageHeaderSize)
            {
                return false;
            }

            ReadOnlySpan<byte> signedContainerBytes = new ReadOnlySpan<byte>(decryptedBuffer, 0, decryptedContentLength);

            if (signedContainerBytes[0] != (byte)MessageContract.MessageType.Signed)
            {
                return false;
            }

            return ParseSignedContainerToPlaintext(
                signedContainerBytes,
                out unauthorizedOperations,
                out logEntries);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(decryptedBuffer, clearArray: true);
        }
    }
}