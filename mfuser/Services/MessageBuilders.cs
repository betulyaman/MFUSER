// Shared message builders for user-mode Agent <-> kernel-mode minifilter.
//
// Output formats (on-the-wire):
//  1) Plaintext:
//     [MESSAGE_HEADER][payload_bytes...]
//
//  2) Signed container:
//     [SIGNED_MESSAGE_HEADER][signed_message_bytes...]
//        where signed_message_bytes = crypto_sign(message)
//        and crypto_sign() output layout is: [signature(crypto_sign_BYTES)][message...]
//
//  3) Encrypted container (of the signed container):
//     [ENCRYPTED_MESSAGE_HEADER][ciphertext...]
//        where ciphertext = crypto_box(signed_container_padded)
//
// IMPORTANT:
// - Do NOT change messageContract struct layouts (Pack=1).
// - All integers are little-endian.

using System.Buffers.Binary;
using System.Runtime.InteropServices;

namespace mfuser.Services;

public static class MessageBuilders
{
    public enum MessageProtection
    {
        Plaintext = 1,
        Signed = 2,
        Encrypted = 4,
        EncryptedSigned = 7
    }

    public static byte[] BuildMessage(
        MessageContract.PayloadType payloadType,
        ReadOnlySpan<byte> payloadBytes,
        uint itemCount,
        MessageProtection protection)
    {
        byte[] plaintextMessage = BuildPlaintextMessage(payloadType, payloadBytes, itemCount);

        return protection switch
        {
            MessageProtection.Plaintext => plaintextMessage,
            MessageProtection.Signed => BuildSignedContainer(plaintextMessage),
            MessageProtection.Encrypted => BuildEncryptedContainer(plaintextMessage),
            MessageProtection.EncryptedSigned => BuildEncryptedSignedContainer(plaintextMessage),
            _ => throw new ArgumentOutOfRangeException(nameof(protection), protection, "Unsupported protection mode.")
        };
    }

    // Plaintext: [MESSAGE_HEADER][payload]
    public static byte[] BuildPlaintextMessage(
        MessageContract.PayloadType payloadType,
        ReadOnlySpan<byte> payloadBytes,
        uint itemCount)
    {
        int messageHeaderSizeBytes = Marshal.SizeOf<MessageContract.PlaintextMessageHeader>();

        // Pack=1 expectation: 20 bytes (Type[1] + Magic[4] + SequenceNumber[4]
        // + HeaderSize[2] + PayloadType[1] + PayloadLengthBytes[4] + ItemCount[4]).
        if (messageHeaderSizeBytes != 20)
        {
            throw new InvalidOperationException(
                $"MESSAGE_HEADER size mismatch. Expected 20, got {messageHeaderSizeBytes}. Check Pack=1.");
        }

        byte[] buffer = new byte[checked(messageHeaderSizeBytes + payloadBytes.Length)];

        int offset = 0;

        // Type
        buffer[offset] = (byte)MessageContract.MessageType.Plaintext;
        offset += sizeof(byte);

        // Magic
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, sizeof(uint)), MessageContract.GuardMessageMagic);
        offset += sizeof(uint);

        // Sequence Number
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, sizeof(uint)), MessageContract.SentMessageSequenceNumber);
        offset += sizeof(uint);

        // HeaderSize
        BinaryPrimitives.WriteUInt16LittleEndian(buffer.AsSpan(offset, sizeof(ushort)), checked((ushort)messageHeaderSizeBytes));
        offset += sizeof(ushort);

        // PayloadType
        buffer[offset] = (byte)payloadType;
        offset += sizeof(byte);

        // PayloadLengthBytes
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, sizeof(uint)), checked((uint)payloadBytes.Length));
        offset += sizeof(uint);

        // ItemCount
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset, sizeof(uint)), itemCount);
        offset += sizeof(uint);

        if (offset != messageHeaderSizeBytes)
        {
            throw new InvalidOperationException("Internal error: MESSAGE_HEADER write size mismatch.");
        }

        payloadBytes.CopyTo(buffer.AsSpan(offset));

        return buffer;
    }

    // Signed container:
    // [SIGNED_MESSAGE_HEADER][signed_message_bytes...]
    // signed_message_bytes = crypto_sign(message) = [signature][message]
    public static byte[] BuildSignedContainer(
        ReadOnlySpan<byte> plaintextMessage)
    {
        int signedHeaderSizeBytes = Marshal.SizeOf<MessageContract.SignedMessageHeader>();
        int signedMessageSizeBytes = checked(plaintextMessage.Length + NaclNativeMethods.crypto_sign_BYTES);

        byte[] container = new byte[checked(signedHeaderSizeBytes + signedMessageSizeBytes)];

        // 1) Write SIGNED_MESSAGE_HEADER
        unsafe
        {
            fixed (byte* containerPtr = container)
            {
                var header = (MessageContract.SignedMessageHeader*)containerPtr;

                header->Type = MessageContract.MessageType.Signed;

                // bytes of (signature + recovered_plaintext)
                header->SignedMessageSize = checked((uint)signedMessageSizeBytes);

                byte[] signerPublicKey = CryptoMaterialProvider.GetUserSignPublicKey();

                fixed (byte* signerPublicKeyPtr = signerPublicKey)
                {
                    Buffer.MemoryCopy(
                        signerPublicKeyPtr,
                        header->SignerPublicKey,
                        NaclNativeMethods.crypto_sign_PUBLICKEYBYTES,
                        NaclNativeMethods.crypto_sign_PUBLICKEYBYTES);
                }

                CryptoMaterialProvider.ClearKeyMaterial(signerPublicKey);
            }
        }

        // 2) Sign directly into the container (no extra signedMessage buffer)
        unsafe
        {
            fixed (byte* containerPtr = container)
            fixed (byte* messagePtr = plaintextMessage)
            {
                byte[] signerSecretKey = CryptoMaterialProvider.GetUserSignSecretKey();

                fixed (byte* secretKeyPtr = signerSecretKey)
                {
                    byte* signedMessageDestinationPtr = containerPtr + signedHeaderSizeBytes;

                    ulong signedMessageLengthBytes;
                    int result = NaclNativeMethods.crypto_sign_ed25519_tweet(
                        (IntPtr)signedMessageDestinationPtr,
                        out signedMessageLengthBytes,
                        (IntPtr)messagePtr,
                        (ulong)plaintextMessage.Length,
                        (IntPtr)secretKeyPtr);

                    CryptoMaterialProvider.ClearKeyMaterial(signerSecretKey);

                    if (result != 0)
                    {
                        throw new InvalidOperationException($"crypto_sign failed. result={result}");
                    }

                    if (signedMessageLengthBytes != (ulong)signedMessageSizeBytes)
                    {
                        throw new InvalidOperationException("crypto_sign returned unexpected signed message length.");
                    }
                }
            }
        }

        return container;
    }

    // Encrypted container:
    // [ENCRYPTED_MESSAGE_HEADER][ciphertext...]
    // ciphertext = crypto_box(signed_container_padded)
    public static byte[] BuildEncryptedContainer(
        ReadOnlySpan<byte> plaintextMessage)
    {
        // crypto_box requires message padding: crypto_box_ZEROBYTES leading zeros.
        byte[] paddedMessage = CreateCryptoBoxPaddedMessage(plaintextMessage);

        Span<byte> nonceBytes = stackalloc byte[NaclNativeMethods.crypto_box_NONCEBYTES];
        FillRandomBytes(nonceBytes);

        int encryptedHeaderSizeBytes = Marshal.SizeOf<MessageContract.EncryptedMessageHeader>();
        int ciphertextSizeBytes = paddedMessage.Length;

        if ((uint)ciphertextSizeBytes > MessageContract.MaxCiphertextBytes)
        {
            throw new InvalidOperationException("Ciphertext exceeds MaxCiphertextBytes.");
        }

        byte[] encryptedContainer = new byte[checked(encryptedHeaderSizeBytes + ciphertextSizeBytes)];

        // write ENCRYPTED_MESSAGE_HEADER.
        unsafe
        {
            fixed (byte* containerPtr = encryptedContainer)
            {
                var header = (MessageContract.EncryptedMessageHeader*)containerPtr;

                header->Type = MessageContract.MessageType.Encrypted;
                header->CiphertextSize = checked((uint)ciphertextSizeBytes);

                for (int i = 0; i < NaclNativeMethods.crypto_box_NONCEBYTES; i++)
                {
                    header->Nonce[i] = nonceBytes[i];
                }

                byte[] senderPublicKey = CryptoMaterialProvider.GetUserEncryptionPublicKey();

                fixed (byte* senderPublicKeyPtr = senderPublicKey)
                {
                    Buffer.MemoryCopy(
                        senderPublicKeyPtr,
                        header->SenderEncryptionPublicKey,
                        NaclNativeMethods.crypto_box_PUBLICKEYBYTES,
                        NaclNativeMethods.crypto_box_PUBLICKEYBYTES);
                }

                CryptoMaterialProvider.ClearKeyMaterial(senderPublicKey);
            }
        }

        // encrypt directly into ciphertext region
        unsafe
        {
            fixed (byte* encryptedContainerPtr = encryptedContainer)
            fixed (byte* paddedMessagePtr = paddedMessage)
            {
                byte[] recipientPublicKey = CryptoMaterialProvider.GetKernelEncryptionPublicKey();
                byte[] senderSecretKey = CryptoMaterialProvider.GetUserEncryptionSecretKey();

                fixed (byte* recipientPublicKeyPtr = recipientPublicKey)
                fixed (byte* senderSecretKeyPtr = senderSecretKey)
                fixed (byte* noncePtr = nonceBytes)
                {
                    byte* ciphertextDestinationPtr = encryptedContainerPtr + encryptedHeaderSizeBytes;

                    int result = NaclNativeMethods.crypto_box_curve25519xsalsa20poly1305_tweet(
                        (IntPtr)ciphertextDestinationPtr,
                        (IntPtr)paddedMessagePtr,
                        (ulong)paddedMessage.Length,
                        (IntPtr)noncePtr,
                        (IntPtr)recipientPublicKeyPtr,
                        (IntPtr)senderSecretKeyPtr);

                    CryptoMaterialProvider.ClearKeyMaterial(recipientPublicKey);
                    CryptoMaterialProvider.ClearKeyMaterial(senderSecretKey);

                    if (result != 0)
                    {
                        throw new InvalidOperationException($"crypto_box failed. result={result}");
                    }
                }
            }
        }

        return encryptedContainer;
    }

    public static byte[] BuildEncryptedSignedContainer(
        ReadOnlySpan<byte> plaintextMessage)
    {
        byte[] signedContainer = BuildSignedContainer(plaintextMessage);

        return BuildEncryptedContainer(signedContainer);
    }

    private static byte[] CreateCryptoBoxPaddedMessage(ReadOnlySpan<byte> message)
    {
        byte[] padded = new byte[checked(NaclNativeMethods.crypto_box_ZEROBYTES + message.Length)];
        message.CopyTo(padded.AsSpan(NaclNativeMethods.crypto_box_ZEROBYTES));

        return padded;
    }

    private static void FillRandomBytes(Span<byte> buffer)
    {
        unsafe
        {
            fixed (byte* bufferPtr = buffer)
            {
                NaclNativeMethods.icr_randombytes((IntPtr)bufferPtr, (ulong)buffer.Length);
            }
        }
    }
}