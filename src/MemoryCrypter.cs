using System.Security.Cryptography;

namespace Cryptonite;

public class MemoryCrypter : AbstractCrypter
{
    public MemoryCrypter(int nmSize, byte[] salt)
    {
        this.DeriveParameters.Salt = salt;
        this.keyBytes = RandomNumberGenerator.GetBytes(nmSize);
    }

    public static MemoryCrypter FromPrivateKey(Span<byte> keyBytes, Span<byte> salt)
    {
        var mc = new MemoryCrypter(keyBytes.Length, salt.ToArray());
        mc.keyBytes = keyBytes.ToArray();
        return mc;
    }
}
