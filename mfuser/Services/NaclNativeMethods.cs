using System.Runtime.InteropServices;

namespace mfuser.Services;

public static class NaclNativeMethods
{
    public const int crypto_box_PUBLICKEYBYTES = 32;
    public const int crypto_box_SECRETKEYBYTES = 32;
    public const int crypto_box_NONCEBYTES = 24;
    public const int crypto_box_ZEROBYTES = 32;
    public const int crypto_box_BOXZEROBYTES = 16;

    public const int crypto_sign_PUBLICKEYBYTES = 32;
    public const int crypto_sign_SECRETKEYBYTES = 64;
    public const int crypto_sign_BYTES = 64;

    [DllImport("icr.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int crypto_box_curve25519xsalsa20poly1305_tweet(
        IntPtr ciphertext,
        IntPtr message,
        ulong messageLength,
        IntPtr nonce,
        IntPtr publicKey,
        IntPtr secretKey);

    [DllImport("icr.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int crypto_box_curve25519xsalsa20poly1305_tweet_open(
        IntPtr plaintextMessage,
        IntPtr ciphertext,
        ulong ciphertextLength,
        IntPtr nonce,
        IntPtr senderPublicKey,
        IntPtr receiverSecretKey);

    [DllImport("icr.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int crypto_sign_ed25519_tweet(
        IntPtr signedMessage,
        out ulong signedMessageLength,
        IntPtr message,
        ulong messageLength,
        IntPtr signerSecretKey);

    [DllImport("icr.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int crypto_sign_ed25519_tweet_open(
        IntPtr message,
        out ulong messageLength,
        IntPtr signature,
        ulong signatureLength,
        IntPtr signerPublicKey);

    [DllImport("icr.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int crypto_box_curve25519xsalsa20poly1305_tweet_keypair(
        IntPtr publicKey,
        IntPtr secretKey);

    [DllImport("icr.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern int crypto_sign_ed25519_tweet_keypair(
        IntPtr publicKey,
        IntPtr secretKey);

    [DllImport("icr.dll", CallingConvention = CallingConvention.Cdecl)]
    public static extern void icr_randombytes(
        IntPtr buffer,
        ulong size);
}