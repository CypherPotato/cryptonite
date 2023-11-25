using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using static System.Net.Mime.MediaTypeNames;
using static System.Runtime.InteropServices.JavaScript.JSType;

namespace Cryptonite;

/// <summary>
/// Provides a class that performs cryptographic operations with a private key generated
/// in the local environment where it is running.
/// </summary>
public class AutoCrypter : AbstractCrypter
{
    private string regionName = null!;
    public int keySize;

    /// <summary>
    /// Creates an new instance of <see cref="AutoCrypter"/> with given parameters.
    /// </summary>
    /// <param name="regionName">The private key name.</param>
    /// <param name="nmSize">The private key size.</param>
    /// <param name="salt">The private key salt.</param>
    public AutoCrypter(string regionName, int nmSize, byte[] salt)
    {
        this.regionName = regionName;
        keySize = nmSize;
        Initialize(regionName, salt);
    }

    /// <summary>
    /// Gets an encryptor sub from this <see cref="AutoCrypter"/>, with it's own private key and
    /// methods.
    /// </summary>
    /// <param name="subRegionName">The name of the sub region that will be derived from this autocrypter.</param>
    /// <returns>Returns a MemoryCrypter derived from this AutoCrypter.</returns>
    public MemoryCrypter GetCrypter(string subRegionName)
    {
        Span<byte> data = Encoding.UTF8.GetBytes(subRegionName);
        var regionPrivateBytes = Derive(data);
        return MemoryCrypter.FromPrivateKey(regionPrivateBytes, this.DeriveParameters.Salt);
    }

    private void Initialize(string regionName, byte[] salt)
    {
        string basePath = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string keyName = $"{regionName}.key";
        string fullPath = Path.Combine(basePath, "private-keys", keyName);

        if (File.Exists(fullPath))
        {
            keyBytes = File.ReadAllBytes(fullPath);
            this.DeriveParameters.Salt = salt;
        }
        else
        {
            keyBytes = StaticOperations.RandomSecureBytes(keySize).ToArray();
            this.DeriveParameters.Salt = salt;
            Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
            File.WriteAllBytes(fullPath, keyBytes);
        }
    }
}