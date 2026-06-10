namespace XWingMLKem768X25519;

internal static class ExceptionText {
    internal static string InvalidDecapsulationKeyLength => "Decapsulation key must be exactly 32 bytes in size.";
    internal static string InvalidEncapsulationKeyLength => "Encapsulation key must be exactly 1216 bytes in size.";
    internal static string InvalidCiphertextLength => "Ciphertext must be exactly 1120 bytes in size.";
    internal static string InvalidSharedSecretLength => "Shared secret must be exactly 32 bytes in size.";
    internal static string OverlappingBuffers => "The ciphertext and shared secret buffers must not overlap.";
    internal static string MissingDecapsulationKey => "The current instance does not contain a decapsulation key.";
    internal static string PlatformNotSupported => "The current platform does not support X-Wing ML-KEM-768-X25519.";
}
