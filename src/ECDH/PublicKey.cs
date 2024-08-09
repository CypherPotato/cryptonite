using Cryptonite.ECDH.Core;

namespace Cryptonite.ECDH
{
    /// <summary>
    /// Represents an ECDH public key.
    /// </summary>
    public readonly struct ECDHPublicKey
    {
        internal readonly ECDHKey _key;

        /// <summary>
        /// Creates an <see cref="ECDHPublicKey"/> from the specified <see cref="ECDHPrivateKey"/>.
        /// </summary>
        /// <param name="privateKey">The ECDH private key.</param>
        public static ECDHPublicKey FromPrivateKey(in ECDHPrivateKey privateKey)
        {
            var pubpk = ECDHAlgorithmService.GetPublicKey(privateKey.GetBytes());
            return new ECDHPublicKey(pubpk);
        }

        /// <summary>
        /// Creates an new intance of the <see cref="ECDHPublicKey"/> structure with the provided public key bytes.
        /// </summary>
        /// <param name="publicKeyBytes">The array of bytes of the public key.</param>
        public ECDHPublicKey(byte[] publicKeyBytes)
        {
            _key = new ECDHKey(publicKeyBytes);
        }

        /// <summary>
        /// Creates an new intance of the <see cref="ECDHPublicKey"/> structure with the provided public key bytes.
        /// </summary>
        /// <param name="publicKeyBytes">The span of bytes of the public key.</param>
        public ECDHPublicKey(ReadOnlySpan<byte> publicKeyBytes)
        {
            _key = new ECDHKey(publicKeyBytes);
        }

        /// <summary>
        /// Gets an string representation of this <see cref="ECDHPublicKey"/>.
        /// </summary>
        /// <returns>An hex string containing this private key bytes.</returns>
        public override string ToString() => $"[ECDHPublicKey 0x{StaticOperations.ToHexString(GetBytes())}]";

        /// <summary>
        /// Gets the public key bytes.
        /// </summary>
        public byte[] GetBytes() => _key.GetBytes();
    }
}
