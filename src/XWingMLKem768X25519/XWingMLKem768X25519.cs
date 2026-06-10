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

    private MLKem? _mlKem;
    private X25519DiffieHellman? _xdh;
    private readonly byte[] _encapsulationKey;
    private readonly byte[]? _decapsulationKey;

    private XWingMLKem768X25519(MLKem mlKem, X25519DiffieHellman? xdh, byte[] encapsulationKey, byte[]? decapsulationKey) {
        Debug.Assert(mlKem is not null);
        Debug.Assert(mlKem.Algorithm == s_mlKem768);
        Debug.Assert(encapsulationKey.Length == EncapsulationKeySizeInBytes);
        Debug.Assert(decapsulationKey is null || decapsulationKey.Length == DecapsulationKeySizeInBytes);
        Debug.Assert((xdh is null) == (decapsulationKey is null));

        _mlKem = mlKem;
        _xdh = xdh;
        _encapsulationKey = encapsulationKey;
        _decapsulationKey = decapsulationKey;
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

        // X-Wing draft section 5.2 expands the 32-byte decapsulation key to
        // the ML-KEM seed pair and X25519 private key with SHAKE256.
        Span<byte> expanded = stackalloc byte[ExpandedDecapsulationKeySizeInBytes];
        Shake256.HashData(source, expanded);

        try {
            // expanded[0:64] is the ML-KEM-768 private seed.
            MLKem mlKem = MLKem.ImportPrivateSeed(s_mlKem768, expanded.Slice(0, s_mlKem768.PrivateSeedSizeInBytes));

            // expanded[64:96] is the X25519 private key.
            X25519DiffieHellman xdh = X25519DiffieHellman.ImportPrivateKey(
                expanded.Slice(s_mlKem768.PrivateSeedSizeInBytes, X25519DiffieHellman.PrivateKeySizeInBytes));

            // The X-Wing encapsulation key is pk_M || pk_X.
            byte[] encapsulationKey = new byte[EncapsulationKeySizeInBytes];
            mlKem.ExportEncapsulationKey(encapsulationKey.AsSpan(0, MLKemEncapsulationKeySizeInBytes));
            xdh.ExportPublicKey(encapsulationKey.AsSpan(MLKemEncapsulationKeySizeInBytes));

            return new XWingMLKem768X25519(mlKem, xdh, encapsulationKey, source.ToArray());
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

        MLKem mlKem = MLKem.ImportEncapsulationKey(s_mlKem768, source.Slice(0, MLKemEncapsulationKeySizeInBytes));
        return new XWingMLKem768X25519(mlKem, null, source.ToArray(), null);
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
        ThrowIfDisposed();

        Span<byte> mlKemCiphertext = ciphertext.Slice(0, MLKemCiphertextSizeInBytes);
        Span<byte> mlKemSharedSecret = stackalloc byte[s_mlKem768.SharedSecretSizeInBytes];
        Span<byte> x25519Ciphertext = ciphertext.Slice(MLKemCiphertextSizeInBytes, X25519DiffieHellman.PublicKeySizeInBytes);
        Span<byte> x25519SharedSecret = stackalloc byte[X25519DiffieHellman.SecretAgreementSizeInBytes];

        try {
            using X25519DiffieHellman xdh = X25519DiffieHellman.GenerateKey();
            _mlKem.Encapsulate(mlKemCiphertext, mlKemSharedSecret);
            xdh.ExportPublicKey(x25519Ciphertext);
            xdh.DeriveRawSecretAgreement(
                _encapsulationKey.AsSpan(MLKemEncapsulationKeySizeInBytes, X25519DiffieHellman.PublicKeySizeInBytes),
                x25519SharedSecret);

            Combiner(
                mlKemSharedSecret,
                x25519SharedSecret,
                x25519Ciphertext,
                _encapsulationKey.AsSpan(MLKemEncapsulationKeySizeInBytes, X25519DiffieHellman.PublicKeySizeInBytes),
                sharedSecret);
        } finally {
            CryptographicOperations.ZeroMemory(mlKemSharedSecret);
            CryptographicOperations.ZeroMemory(x25519SharedSecret);
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
        ThrowIfDisposed();
        ThrowIfNoDecapsulationKey();

        ReadOnlySpan<byte> x25519Ciphertext = ciphertext.Slice(MLKemCiphertextSizeInBytes, X25519DiffieHellman.PublicKeySizeInBytes);
        Span<byte> mlKemSharedSecret = stackalloc byte[s_mlKem768.SharedSecretSizeInBytes];
        Span<byte> x25519SharedSecret = stackalloc byte[X25519DiffieHellman.SecretAgreementSizeInBytes];

        try {
            _mlKem.Decapsulate(ciphertext.Slice(0, MLKemCiphertextSizeInBytes), mlKemSharedSecret);
            _xdh.DeriveRawSecretAgreement(x25519Ciphertext, x25519SharedSecret);
            Combiner(
                mlKemSharedSecret,
                x25519SharedSecret,
                x25519Ciphertext,
                _encapsulationKey.AsSpan(MLKemEncapsulationKeySizeInBytes, X25519DiffieHellman.PublicKeySizeInBytes),
                sharedSecret);
        } finally {
            CryptographicOperations.ZeroMemory(mlKemSharedSecret);
            CryptographicOperations.ZeroMemory(x25519SharedSecret);
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
        ThrowIfDisposed();
        return _encapsulationKey.ToArray();
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
        ThrowIfDisposed();
        _encapsulationKey.CopyTo(destination);
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
        ThrowIfDisposed();
        ThrowIfNoDecapsulationKey();
        return _decapsulationKey.ToArray();
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
        ThrowIfDisposed();
        ThrowIfNoDecapsulationKey();
        _decapsulationKey.CopyTo(destination);
    }

    /// <summary>
    ///   Releases all resources used by the current instance of the <see cref="XWingMLKem768X25519"/> class.
    /// </summary>
    public void Dispose() {
        _mlKem?.Dispose();
        _xdh?.Dispose();
        _mlKem = null;
        _xdh = null;

        if (_decapsulationKey is not null) {
            CryptographicOperations.ZeroMemory(_decapsulationKey);
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

    [MemberNotNull(nameof(_mlKem))]
    private void ThrowIfDisposed() {
        ObjectDisposedException.ThrowIf(_mlKem is null, this);
    }

    [MemberNotNull(nameof(_decapsulationKey), nameof(_xdh))]
    private void ThrowIfNoDecapsulationKey() {
        if (_decapsulationKey is null || _xdh is null) {
            throw new InvalidOperationException(ExceptionText.MissingDecapsulationKey);
        }
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
}
