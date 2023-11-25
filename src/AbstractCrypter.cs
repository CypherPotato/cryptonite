using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptonite;

/// <summary>
/// Provides a base class for AutoCrypters.
/// </summary>
public abstract class AbstractCrypter
{
    protected byte[] keyBytes = null!;

    /// <summary>
    /// Gets or sets the key derive parameters.
    /// </summary>
    /// <remarks>The Salt property is automatically overriden by the constructor salt.</remarks>
    public PBKDF2Parameters DeriveParameters { get; set; } = new PBKDF2Parameters()
    {
        HashAlgorithm = HashAlgorithmName.SHA256,
        Iterations = 12513,
        Salt = new byte[] { 0 }
    };

    /// <summary>
    /// Attempts to derive the specified input data from the private key, and tests whether it
    /// is the same as the information already derived.
    /// </summary>
    /// <param name="data">The information that will be tested with the derived key.</param>
    /// <param name="derive">The information already derived.</param>
    /// <returns>A boolean indicating whether the drift is the same or not.</returns>
    public bool CheckDerive(Span<byte> data, Span<byte> derive)
    {
        var test = Derive(data);
        return StaticOperations.TimingSafeEqual(test, derive);
    }

    /// <summary>
    /// Attempts to derive the specified input data from the private key, and tests whether it
    /// is the same as the information already derived.
    /// </summary>
    /// <param name="text">The information that will be tested with the derived key.</param>
    /// <param name="encoding">The encoding for decoding the text message into an byte span.</param>
    /// <param name="derive">The information already derived.</param>
    /// <returns>A boolean indicating whether the drift is the same or not.</returns>
    public bool CheckDerive(string text, Encoding encoding, Span<byte> derive)
    {
        Span<byte> data = encoding.GetBytes(text);
        var test = Derive(data);
        return StaticOperations.TimingSafeEqual(test, derive);
    }

    /// <summary>
    /// Attempts to derive the specified input data from the private key, and tests whether it
    /// is the same as the information already derived.
    /// </summary>
    /// <param name="data">The information that will be tested with the derived key.</param>
    /// <param name="derive">The information already derived.</param>
    /// <returns>A boolean indicating whether the drift is the same or not.</returns>
    public bool CheckDerive(string text, Span<byte> derive)
    {
        return CheckDerive(text, Encoding.UTF8, derive);
    }

    /// <summary>
    /// Transforms the information into a derivative of the same size as the private key and applies the
    /// private key to the encrypted information.
    /// </summary>
    /// <param name="data">Information of any size that will be derived.</param>
    /// <returns>Gets a key derived from the information.</returns>
    public Span<byte> Derive(Span<byte> data)
    {
        Span<byte> hashedData = StaticOperations.Pbkdf2Derive(data, keyBytes.Length, DeriveParameters);
        Span<byte> xorBytes = StaticOperations.XorGate(keyBytes, hashedData);
        return xorBytes;
    }

    /// <summary>
    /// Transforms the information into a derivative of the same size as the private key and applies the
    /// private key to the encrypted information.
    /// </summary>
    /// <param name="text">Information of any size that will be derived.</param>
    /// <param name="encoding">Encoding which will be used to decode the text message.</param>
    /// <returns>Gets a key derived from the information.</returns>
    public Span<byte> Derive(string text, Encoding encoding)
    {
        Span<byte> data = encoding.GetBytes(text);
        return Derive(data);
    }

    /// <summary>
    /// Transforms the information into a derivative of the same size as the private key and applies the
    /// private key to the encrypted information.
    /// </summary>
    /// <param name="text">Information of any size that will be derived.</param>
    /// <returns>Gets a key derived from the information.</returns>
    public Span<byte> Derive(string text)
    {
        return Derive(text, Encoding.UTF8);
    }

    /// <summary>
    /// Applies a one-way XOR operation to the provided information.
    /// </summary>
    /// <param name="data">The information that will be encrypted by the private key.</param>
    /// <returns>The information in the same size, encrypted or decrypted by the private key.</returns>
    public Span<byte> Turn(Span<byte> data)
    {
        Span<byte> deriveKey = StaticOperations.Pbkdf2Derive(keyBytes, data.Length, DeriveParameters);
        Span<byte> xorBytes = StaticOperations.XorGate(data, deriveKey);
        return xorBytes;
    }

    /// <summary>
    /// Applies a one-way XOR operation to the provided information.
    /// </summary>
    /// <param name="text">Information of any size that will be encripted.</param>
    /// <param name="encoding">Encoding which will be used to decode the text message.</param>
    /// <returns>The information in the same size, encrypted or decrypted by the private key.</returns>
    public Span<byte> Turn(string text, Encoding encoding)
    {
        Span<byte> data = encoding.GetBytes(text);
        return Turn(data);
    }

    /// <summary>
    /// Applies a one-way XOR operation to the provided information.
    /// </summary>
    /// <param name="text">Information of any size that will be encripted.</param>
    /// <returns>The information in the same size, encrypted or decrypted by the private key.</returns>
    public Span<byte> Turn(string text)
    {
        return Turn(text, Encoding.UTF8);
    }
}
