using System.Security.Cryptography;

namespace Cryptonite;

/// <summary>
/// Provides an <see cref="AbstractCrypter"/> for memory operations.
/// </summary>
public class MemoryCrypter : AbstractCrypter
{
    public MemoryCrypter(int nmSize, byte[] salt)
    {
        this.DeriveParameters.Salt = salt;
        this.keyBytes = RandomNumberGenerator.GetBytes(nmSize);
    }

    /// <summary>
    /// Creates an new <see cref="MemoryCrypter"/> from the specified private key and
    /// salt.
    /// </summary>
    /// <param name="keyBytes">The private key bytes.</param>
    /// <param name="salt">The salt bytes.</param>
    /// <returns></returns>
    public static MemoryCrypter FromPrivateKey(Span<byte> keyBytes, Span<byte> salt)
    {
        var mc = new MemoryCrypter(keyBytes.Length, salt.ToArray());
        mc.keyBytes = keyBytes.ToArray();
        return mc;
    }
}
