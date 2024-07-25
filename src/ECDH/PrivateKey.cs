using Cryptonite.ECDH.Core;

namespace Cryptonite.ECDH
{
    /// <summary>
    /// Represents an ECDH private key.
    /// </summary>
    public readonly struct ECDHPrivateKey
    {
        internal readonly byte[] _keyBytes;

        /// <summary>
        /// Creates an new, random ECDH private key.
        /// </summary>
        public static ECDHPrivateKey Create()
        {
            var randomPkBytes = ECDHAlgorithmService.GetRandomPrivateKey();
            return new ECDHPrivateKey(randomPkBytes);
        }

        /// <summary>
        /// Creates an new intance of the <see cref="ECDHPrivateKey"/> structure with the provided private key bytes.
        /// </summary>
        /// <param name="privateKeyBytes">The span of bytes of the private key.</param>
        public ECDHPrivateKey(ReadOnlyMemory<byte> privateKeyBytes)
        {
            if (privateKeyBytes.Length != ECDHAlgorithmService.PrivateKeySizeInBytes) throw new ArgumentException("Private key byte length should be exact 32 bytes-long.");
            _keyBytes = privateKeyBytes.ToArray();
        }

        /// <summary>
        /// Creates an new intance of the <see cref="ECDHPrivateKey"/> structure with the provided private key bytes.
        /// </summary>
        /// <param name="privateKeyBytes">The array of bytes of the private key.</param>
        public ECDHPrivateKey(byte[] privateKeyBytes)
        {
            if (privateKeyBytes.Length != ECDHAlgorithmService.PrivateKeySizeInBytes) throw new ArgumentException("Private key byte length should be exact 32 bytes-long.");
            _keyBytes = privateKeyBytes;
        }

        /// <summary>
        /// Gets the private key bytes.
        /// </summary>
        public byte[] GetBytes() => _keyBytes.ToArray();

        /// <summary>
        /// Gets the <see cref="ECDHPublicKey"/> associated with this private key.
        /// </summary>
        public ECDHPublicKey GetPublicKey()
        {
            return ECDHPublicKey.FromPrivateKey(this);
        }

        /// <summary>
        /// Calculates and gets the <see cref="ECDHSharedKey"/> for the specified public key.
        /// </summary>
        /// <param name="peerPublicKey">The other party public key.</param>
        public ECDHSharedKey GetSharedKey(ECDHPublicKey peerPublicKey)
        {
            return new ECDHSharedKey(this, peerPublicKey);
        }

        /// <summary>
        /// Gets an string representation of this <see cref="ECDHPrivateKey"/>.
        /// </summary>
        /// <returns>An hex string containing this private key bytes.</returns>
        public override string ToString() => string.Join("", GetBytes().Select(b => b.ToString("x2")));
    }
}