public static class CryptoMaterialProvider
{
    private static string KernelSignPublicKeyFilePath { get; } = @"C:\windows\minifilter_secure_folder\kernel_sign_pub_key.txt";
    private static string KernelEncryptionPublicKeyFilePath { get; } = @"C:\windows\minifilter_secure_folder\kernel_encrypt_pub_key.txt";

    private static string UserEncryptionPublicKeyFilePath { get; } = @"C:\windows\minifilter_secure_folder\user_encrypt_pub_key.txt";
    private static string UserEncryptionSecretKeyFilePath { get; } = @"C:\windows\minifilter_secure_folder\user_encrypt_pri_key.txt";

    private static string UserSignPublicKeyFilePath { get; } = @"C:\windows\minifilter_secure_folder\user_sign_pub_key.txt";
    private static string UserSignSecretKeyFilePath { get; } = @"C:\windows\minifilter_secure_folder\user_sign_pri_key.txt";

    public static byte[] GetKernelEncryptionPublicKey()
    {
        return ReadKeyFile(
            KernelEncryptionPublicKeyFilePath,
            NaclNativeMethods.crypto_box_PUBLICKEYBYTES);
    }

    public static byte[] GetKernelSignPublicKey()
    {
        return ReadKeyFile(
            KernelSignPublicKeyFilePath,
            NaclNativeMethods.crypto_sign_PUBLICKEYBYTES);
    }

    public static byte[] GetUserEncryptionPublicKey()
    {
        return ReadKeyFile(
            UserEncryptionPublicKeyFilePath,
            NaclNativeMethods.crypto_box_PUBLICKEYBYTES);
    }

    public static byte[] GetUserEncryptionSecretKey()
    {
        return ReadKeyFile(
            UserEncryptionSecretKeyFilePath,
            NaclNativeMethods.crypto_box_SECRETKEYBYTES);
    }

    public static byte[] GetUserSignPublicKey()
    {
        return ReadKeyFile(
            UserSignPublicKeyFilePath,
            NaclNativeMethods.crypto_sign_PUBLICKEYBYTES);
    }

    public static byte[] GetUserSignSecretKey()
    {
        return ReadKeyFile(
            UserSignSecretKeyFilePath,
            NaclNativeMethods.crypto_sign_SECRETKEYBYTES);
    }

    public static void ClearKeyMaterial(byte[]? keyMaterial)
    {
        if (keyMaterial is null)
        {
            return;
        }

        Array.Clear(keyMaterial, 0, keyMaterial.Length);
    }

    private static byte[] ReadKeyFile(string filePath, int expectedLengthBytes)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            throw new ArgumentException("Key file path is null or empty.", nameof(filePath));
        }

        byte[] fileBytes;

        try
        {
            fileBytes = File.ReadAllBytes(filePath);
        }
        catch (Exception exceptionObject)
        {
            throw new InvalidOperationException($"Failed to read key file '{filePath}'.", exceptionObject);
        }

        if (fileBytes.Length != expectedLengthBytes)
        {
            Array.Clear(fileBytes, 0, fileBytes.Length);

            throw new InvalidOperationException(
                $"Key file '{filePath}' size mismatch. Expected {expectedLengthBytes} bytes, got {fileBytes.Length} bytes.");
        }

        return fileBytes;
    }
}