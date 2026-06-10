using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;

namespace XWingMLKem768X25519;

/// <summary>
///   Implements the X-Wing composite KEM built from ML-KEM-768 and X25519.
/// </summary>
/// <remarks>
///   <para>The X-Wing algorithm is specified by <see href="https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/" />.</para>
///   <para>
///     Instances of this object are not thread safe. Callers must ensure instances are only ever accessed exclusively by
///     a single thread.
///   </para>
/// </remarks>
public sealed class XWingMLKem768X25519 : IDisposable {
    /// <summary>
    ///   The size of an X-Wing decapsulation key, in bytes.
    /// </summary>
    public const int DecapsulationKeySizeInBytes = 32;

    /// <summary>
    ///   The size of an X-Wing encapsulation key, in bytes.
    /// </summary>
    public const int EncapsulationKeySizeInBytes = 1216;

    /// <summary>
    ///   The size of an X-Wing ciphertext, in bytes.
    /// </summary>
    public const int CiphertextSizeInBytes = 1120;

    /// <summary>
    ///   The size of an X-Wing shared secret, in bytes.
    /// </summary>
    public const int SharedSecretSizeInBytes = 32;

    private const int MLKemEncapsulationKeySizeInBytes = 1184;
    private const int MLKemCiphertextSizeInBytes = 1088;
    private const int ExpandedDecapsulationKeySizeInBytes = 96;

    private static ReadOnlySpan<byte> XWingLabel => "\\.//^\\"u8;
    private static readonly MLKemAlgorithm s_mlKem768 = MLKemAlgorithm.MLKem768;

    private XWingKey _key;

    private XWingMLKem768X25519(XWingKey key) {
        _key = key;
    }

    /// <summary>
    ///   Gets a value indicating whether X-Wing ML-KEM-768-X25519 is supported on the current platform.
    /// </summary>
    public static bool IsSupported =>
        MLKem.IsSupported && X25519DiffieHellman.IsSupported && SHA3_256.IsSupported && Shake256.IsSupported;

    /// <summary>
    ///   Generates a new X-Wing key.
    /// </summary>
    /// <returns>A new X-Wing key.</returns>
    /// <exception cref="PlatformNotSupportedException">
    ///   The current platform does not support X-Wing ML-KEM-768-X25519.
    /// </exception>
    public static XWingMLKem768X25519 GenerateKey() {
        ThrowIfNotSupported();

        // X-Wing draft section 5.2 defines key generation as GenerateKeyPairDerand(random(32)).
        // We don't expose the de-random key generator, this is functionally the same as importing a random
        // decapsulation key.
        Span<byte> decapsulationKey = stackalloc byte[DecapsulationKeySizeInBytes];
        RandomNumberGenerator.Fill(decapsulationKey);

        try {
            return ImportDecapsulationKey(decapsulationKey);
        } finally {
            CryptographicOperations.ZeroMemory(decapsulationKey);
        }
    }

    /// <summary>
    ///   Imports an X-Wing decapsulation key.
    /// </summary>
    /// <param name="source">The raw X-Wing decapsulation key.</param>
    /// <returns>A new X-Wing key.</returns>
    /// <exception cref="ArgumentException">
    ///   <paramref name="source"/> is not exactly <see cref="DecapsulationKeySizeInBytes"/> bytes.
    /// </exception>
    /// <exception cref="PlatformNotSupportedException">
    ///   The current platform does not support X-Wing ML-KEM-768-X25519.
    /// </exception>
    public static XWingMLKem768X25519 ImportDecapsulationKey(ReadOnlySpan<byte> source) {
        ThrowIfNotSupported();
        ThrowIfDecapsulationKeySizeIncorrect(source, nameof(source));

        // SHAKE256(sk, 96*8) # expand sk to 96 bytes using SHAKE256
        Span<byte> expanded = stackalloc byte[ExpandedDecapsulationKeySizeInBytes];
        Shake256.HashData(source, expanded);

        try {
            // (pk_M, sk_M) = ML-KEM-768.KeyGen_internal(expanded[0:32], expanded[32:64])
            // MLKem doesn't expose KeyGen_internal, but we can implement it in terms of importing a private seed
            // since we know that a private seed is defined as d || z.
            MLKem mlKem = MLKem.ImportPrivateSeed(s_mlKem768, expanded.Slice(0, s_mlKem768.PrivateSeedSizeInBytes));

            // expanded[64:96] is the X25519 private key.
            X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(
                expanded.Slice(s_mlKem768.PrivateSeedSizeInBytes, X25519DiffieHellman.PrivateKeySizeInBytes));

            // The X-Wing encapsulation key is pk_M || pk_X.
            byte[] encapsulationKey = new byte[EncapsulationKeySizeInBytes];


            // pk_M
            mlKem.ExportEncapsulationKey(encapsulationKey.AsSpan(0, MLKemEncapsulationKeySizeInBytes));

            // pk_X = X25519(sk_X, X25519_BASE)
            // X25519DiffieHellman uses the default base point, so exporting the public key form the private key
            // is the same as X25519(sk_X, 9)
            xdh.ExportPublicKey(encapsulationKey.AsSpan(MLKemEncapsulationKeySizeInBytes));

            return new XWingMLKem768X25519(new XWingPrivateKey(mlKem, xdh, encapsulationKey, source.ToArray()));
        } finally {
            CryptographicOperations.ZeroMemory(expanded);
        }
    }

    /// <inheritdoc cref="ImportDecapsulationKey(ReadOnlySpan{byte})"/>
    /// <exception cref="ArgumentNullException">
    ///   <paramref name="source"/> is <see langword="null"/>.
    /// </exception>
    public static XWingMLKem768X25519 ImportDecapsulationKey(byte[] source) {
        ArgumentNullException.ThrowIfNull(source);
        return ImportDecapsulationKey(source.AsSpan());
    }

    /// <summary>
    ///   Imports an X-Wing encapsulation key.
    /// </summary>
    /// <param name="source">The raw X-Wing encapsulation key.</param>
    /// <returns>A new X-Wing key.</returns>
    /// <exception cref="ArgumentException">
    ///   <paramref name="source"/> is not exactly <see cref="EncapsulationKeySizeInBytes"/> bytes.
    /// </exception>
    /// <exception cref="CryptographicException">
    ///   <paramref name="source"/> is not a valid ML-KEM-768 encapsulation key.
    /// </exception>
    /// <exception cref="PlatformNotSupportedException">
    ///   The current platform does not support X-Wing ML-KEM-768-X25519.
    /// </exception>
    public static XWingMLKem768X25519 ImportEncapsulationKey(ReadOnlySpan<byte> source) {
        ThrowIfNotSupported();
        ThrowIfEncapsulationKeySizeIncorrect(source, nameof(source));

        MLKem kem = MLKem.ImportEncapsulationKey(s_mlKem768, source.Slice(0, MLKemEncapsulationKeySizeInBytes));
        return new XWingMLKem768X25519(new XWingPublicKey(kem, source.ToArray()));
    }

    /// <inheritdoc cref="ImportEncapsulationKey(ReadOnlySpan{byte})"/>
    /// <exception cref="ArgumentNullException">
    ///   <paramref name="source"/> is <see langword="null"/>.
    /// </exception>
    public static XWingMLKem768X25519 ImportEncapsulationKey(byte[] source) {
        ArgumentNullException.ThrowIfNull(source);
        return ImportEncapsulationKey(source.AsSpan());
    }

    /// <summary>
    ///   Encapsulates a shared secret to this X-Wing key's encapsulation key.
    /// </summary>
    /// <param name="ciphertext">When this method returns, contains the X-Wing ciphertext.</param>
    /// <param name="sharedSecret">When this method returns, contains the shared secret.</param>
    /// <exception cref="ArgumentException">
    ///   <para><paramref name="ciphertext"/> is not exactly <see cref="CiphertextSizeInBytes"/> bytes.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="sharedSecret"/> is not exactly <see cref="SharedSecretSizeInBytes"/> bytes.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="ciphertext"/> and <paramref name="sharedSecret"/> overlap.</para>
    /// </exception>
    /// <exception cref="CryptographicException">
    ///   The ML-KEM-768 encapsulation key check fails.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public void Encapsulate(Span<byte> ciphertext, Span<byte> sharedSecret) {
        ThrowIfCiphertextSizeIncorrect(ciphertext, nameof(ciphertext));
        ThrowIfSharedSecretSizeIncorrect(sharedSecret, nameof(sharedSecret));
        ThrowIfOverlapping(ciphertext, sharedSecret, nameof(sharedSecret));

        (MLKem kem, byte[] encapsulationKey) = _key switch {
            XWingPublicKey pub => (pub.Kem, pub.EncapsulationKey),
            XWingPrivateKey pk => (pk.Kem, pk.EncapsulationKey),
            Disposed => throw CreateObjectDisposedException(),
        };

        Span<byte> ct_M = ciphertext.Slice(0, MLKemCiphertextSizeInBytes);
        Span<byte> ss_M = stackalloc byte[s_mlKem768.SharedSecretSizeInBytes];
        Span<byte> ct_X = ciphertext.Slice(MLKemCiphertextSizeInBytes, X25519DiffieHellman.PublicKeySizeInBytes);
        Span<byte> ss_X = stackalloc byte[X25519DiffieHellman.SecretAgreementSizeInBytes];

        ReadOnlySpan<byte> pk_X = encapsulationKey.AsSpan(
            MLKemEncapsulationKeySizeInBytes,
            X25519DiffieHellman.PublicKeySizeInBytes);

        // pk_M is already represented by the ML-KEM instance.

        try {
            // ek_X = random(32), X25519 key generation is functionally a random key.
            using X25519DiffieHellman xdh = X25519DiffieHellman.GenerateKey();

            // ct_X = X25519(ek_X, X25519_BASE) exporting the public key is functionally the same as X25519(ek_X, 9)
            xdh.ExportPublicKey(ct_X);

            // ss_X = X25519(ek_X, pk_X)
            xdh.DeriveRawSecretAgreement(
                encapsulationKey.AsSpan(MLKemEncapsulationKeySizeInBytes, X25519DiffieHellman.SecretAgreementSizeInBytes),
                ss_X);

            kem.Encapsulate(ct_M, ss_M);

            // ss = Combiner(ss_M, ss_X, ct_X, pk_X)
            Combiner(
                ss_M,
                ss_X,
                ct_X,
                pk_X,
                sharedSecret);

            // ct = concat(ct_M, ct_X)
            // the ciphertext (ct) was written directly to the buffer
        } finally {
            CryptographicOperations.ZeroMemory(ss_M);
            CryptographicOperations.ZeroMemory(ss_X);
        }
    }

    /// <summary>
    ///   Encapsulates a shared secret to this X-Wing key's encapsulation key.
    /// </summary>
    /// <param name="ciphertext">When this method returns, contains the X-Wing ciphertext.</param>
    /// <param name="sharedSecret">When this method returns, contains the shared secret.</param>
    /// <exception cref="CryptographicException">
    ///   The ML-KEM-768 encapsulation key check fails.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public void Encapsulate(out byte[] ciphertext, out byte[] sharedSecret) {
        ciphertext = new byte[CiphertextSizeInBytes];
        sharedSecret = new byte[SharedSecretSizeInBytes];
        Encapsulate(ciphertext, sharedSecret);
    }

    /// <summary>
    ///   Decapsulates an X-Wing ciphertext.
    /// </summary>
    /// <param name="ciphertext">The X-Wing ciphertext.</param>
    /// <param name="sharedSecret">When this method returns, contains the shared secret.</param>
    /// <exception cref="ArgumentException">
    ///   <para><paramref name="ciphertext"/> is not exactly <see cref="CiphertextSizeInBytes"/> bytes.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="sharedSecret"/> is not exactly <see cref="SharedSecretSizeInBytes"/> bytes.</para>
    ///   <para> -or- </para>
    ///   <para><paramref name="ciphertext"/> and <paramref name="sharedSecret"/> overlap.</para>
    /// </exception>
    /// <exception cref="InvalidOperationException">
    ///   The current instance does not contain a decapsulation key.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public void Decapsulate(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret) {
        ThrowIfCiphertextSizeIncorrect(ciphertext, nameof(ciphertext));
        ThrowIfSharedSecretSizeIncorrect(sharedSecret, nameof(sharedSecret));
        ThrowIfOverlapping(ciphertext, sharedSecret, nameof(sharedSecret));

        (MLKem kem, X25519DiffieHellman xdh, byte[] encapsulationKey) = _key switch {
            Disposed => throw CreateObjectDisposedException(),
            XWingPublicKey => throw CreateNoDecapsulationException(),
            XWingPrivateKey pk => (pk.Kem, pk.Xdh, pk.EncapsulationKey),
        };

        ReadOnlySpan<byte> ct_M = ciphertext.Slice(0, MLKemCiphertextSizeInBytes);
        ReadOnlySpan<byte> ct_X = ciphertext.Slice(MLKemCiphertextSizeInBytes, X25519DiffieHellman.PublicKeySizeInBytes);
        ReadOnlySpan<byte> pk_X = encapsulationKey.AsSpan(MLKemEncapsulationKeySizeInBytes, X25519DiffieHellman.PublicKeySizeInBytes);
        Span<byte> ss_M = stackalloc byte[s_mlKem768.SharedSecretSizeInBytes];
        Span<byte> ss_X = stackalloc byte[X25519DiffieHellman.SecretAgreementSizeInBytes];

        try {
            kem.Decapsulate(ct_M, ss_M);
            xdh.DeriveRawSecretAgreement(ct_X, ss_X);
            Combiner(ss_M, ss_X, ct_X, pk_X, sharedSecret);
        } finally {
            CryptographicOperations.ZeroMemory(ss_M);
            CryptographicOperations.ZeroMemory(ss_X);
        }
    }

    /// <summary>
    ///   Decapsulates an X-Wing ciphertext.
    /// </summary>
    /// <param name="ciphertext">The X-Wing ciphertext.</param>
    /// <returns>The shared secret.</returns>
    /// <exception cref="ArgumentNullException">
    ///   <paramref name="ciphertext"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    ///   <paramref name="ciphertext"/> is not exactly <see cref="CiphertextSizeInBytes"/> bytes.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    ///   The current instance does not contain a decapsulation key.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public byte[] Decapsulate(byte[] ciphertext) {
        ArgumentNullException.ThrowIfNull(ciphertext);
        byte[] sharedSecret = new byte[SharedSecretSizeInBytes];
        Decapsulate(ciphertext.AsSpan(), sharedSecret);
        return sharedSecret;
    }

    /// <summary>
    ///   Exports the raw X-Wing encapsulation key.
    /// </summary>
    /// <returns>The raw X-Wing encapsulation key.</returns>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public byte[] ExportEncapsulationKey() {
        byte[] result = new byte[EncapsulationKeySizeInBytes];
        ExportEncapsulationKey(result);
        return result;
    }

    /// <summary>
    ///   Exports the raw X-Wing encapsulation key.
    /// </summary>
    /// <param name="destination">The buffer to receive the raw X-Wing encapsulation key.</param>
    /// <exception cref="ArgumentException">
    ///   <paramref name="destination"/> is not exactly <see cref="EncapsulationKeySizeInBytes"/> bytes.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public void ExportEncapsulationKey(Span<byte> destination) {
        ThrowIfEncapsulationKeySizeIncorrect(destination, nameof(destination));

        switch (_key) {
            case Disposed:
                throw CreateObjectDisposedException();
            case XWingPublicKey pub:
                Debug.Assert(pub.EncapsulationKey.Length == destination.Length);
                pub.EncapsulationKey.CopyTo(destination);
                break;
            case XWingPrivateKey pk:
                Debug.Assert(pk.EncapsulationKey.Length == destination.Length);
                pk.EncapsulationKey.CopyTo(destination);
                break;
            default:
                throw new UnreachableException();
        }
    }

    /// <summary>
    ///   Exports the raw X-Wing decapsulation key.
    /// </summary>
    /// <returns>The raw X-Wing decapsulation key.</returns>
    /// <exception cref="InvalidOperationException">
    ///   The current instance does not contain a decapsulation key.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public byte[] ExportDecapsulationKey() {
        byte[] result = new byte[DecapsulationKeySizeInBytes];
        ExportDecapsulationKey(result);
        return result;
    }

    /// <summary>
    ///   Exports the raw X-Wing decapsulation key.
    /// </summary>
    /// <param name="destination">The buffer to receive the raw X-Wing decapsulation key.</param>
    /// <exception cref="ArgumentException">
    ///   <paramref name="destination"/> is not exactly <see cref="DecapsulationKeySizeInBytes"/> bytes.
    /// </exception>
    /// <exception cref="InvalidOperationException">
    ///   The current instance does not contain a decapsulation key.
    /// </exception>
    /// <exception cref="ObjectDisposedException">
    ///   The current instance has been disposed.
    /// </exception>
    public void ExportDecapsulationKey(Span<byte> destination) {
        ThrowIfDecapsulationKeySizeIncorrect(destination, nameof(destination));

        switch (_key) {
            case Disposed:
                throw CreateObjectDisposedException();
            case XWingPublicKey:
                throw CreateNoDecapsulationException();
            case XWingPrivateKey pk:
                Debug.Assert(pk.DecapsulationKey.Length == destination.Length);
                pk.DecapsulationKey.CopyTo(destination);
                break;
            default:
                throw new UnreachableException();
        }
    }

    /// <summary>
    ///   Releases all resources used by the current instance of the <see cref="XWingMLKem768X25519"/> class.
    /// </summary>
    public void Dispose() {
        switch (_key) {
            case XWingPrivateKey privateKey:
                privateKey.Kem.Dispose();
                privateKey.Xdh.Dispose();
                CryptographicOperations.ZeroMemory(privateKey.DecapsulationKey);
                _key = Disposed.Instance;
                break;
            case XWingPublicKey publicKey:
                publicKey.Kem.Dispose();
                _key = Disposed.Instance;
                break;
            case Disposed:
                break; // no-op
        }
    }

    private static void Combiner(
        ReadOnlySpan<byte> mlKemSharedSecret,
        ReadOnlySpan<byte> x25519SharedSecret,
        ReadOnlySpan<byte> x25519Ciphertext,
        ReadOnlySpan<byte> x25519PublicKey,
        Span<byte> sharedSecret) {

        using IncrementalHash hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA3_256);
        hash.AppendData(mlKemSharedSecret);
        hash.AppendData(x25519SharedSecret);
        hash.AppendData(x25519Ciphertext);
        hash.AppendData(x25519PublicKey);
        hash.AppendData(XWingLabel);
        hash.GetHashAndReset(sharedSecret);
    }

    private static void ThrowIfNotSupported() {
        if (!IsSupported) {
            throw new PlatformNotSupportedException(ExceptionText.PlatformNotSupported);
        }
    }

    private static Exception CreateNoDecapsulationException() {
        return new InvalidOperationException(ExceptionText.MissingDecapsulationKey);
    }

    private static Exception CreateObjectDisposedException() {
        return new ObjectDisposedException(typeof(XWingMLKem768X25519).FullName);
    }

    private static void ThrowIfDecapsulationKeySizeIncorrect(ReadOnlySpan<byte> key, string paramName) {
        if (key.Length != DecapsulationKeySizeInBytes) {
            throw new ArgumentException(ExceptionText.InvalidDecapsulationKeyLength, paramName);
        }
    }

    private static void ThrowIfEncapsulationKeySizeIncorrect(ReadOnlySpan<byte> key, string paramName) {
        if (key.Length != EncapsulationKeySizeInBytes) {
            throw new ArgumentException(ExceptionText.InvalidEncapsulationKeyLength, paramName);
        }
    }

    private static void ThrowIfCiphertextSizeIncorrect(ReadOnlySpan<byte> ciphertext, string paramName) {
        if (ciphertext.Length != CiphertextSizeInBytes) {
            throw new ArgumentException(ExceptionText.InvalidCiphertextLength, paramName);
        }
    }

    private static void ThrowIfCiphertextSizeIncorrect(Span<byte> ciphertext, string paramName) {
        if (ciphertext.Length != CiphertextSizeInBytes) {
            throw new ArgumentException(ExceptionText.InvalidCiphertextLength, paramName);
        }
    }

    private static void ThrowIfSharedSecretSizeIncorrect(Span<byte> sharedSecret, string paramName) {
        if (sharedSecret.Length != SharedSecretSizeInBytes) {
            throw new ArgumentException(ExceptionText.InvalidSharedSecretLength, paramName);
        }
    }

    private static void ThrowIfOverlapping(ReadOnlySpan<byte> ciphertext, Span<byte> sharedSecret, string paramName) {
        if (ciphertext.Overlaps(sharedSecret)) {
            throw new ArgumentException(ExceptionText.OverlappingBuffers, paramName);
        }
    }


    private record XWingPublicKey(MLKem Kem, byte[] EncapsulationKey);
    private record XWingPrivateKey(MLKem Kem, X25519DiffieHellman Xdh, byte[] EncapsulationKey, byte[] DecapsulationKey);

    private record Disposed {
        public static Disposed Instance { get; } = new();
    }

    private union XWingKey(XWingPublicKey, XWingPrivateKey, Disposed);
}
