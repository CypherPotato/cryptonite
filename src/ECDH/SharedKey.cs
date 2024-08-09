using Cryptonite.ECDH.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptonite.ECDH
{
    /// <summary>
    /// Represents an ECDH shared key.
    /// </summary>
    public readonly struct ECDHSharedKey
    {
        internal readonly ECDHKey _key;

        /// <summary>
        /// Creates an new intance of the <see cref="ECDHSharedKey"/> structure with the provided shared key bytes.
        /// </summary>
        /// <param name="publicKeyBytes">The array of bytes of the public key.</param>
        public ECDHSharedKey(byte[] keyBytes)
        {
            _key = new ECDHKey(keyBytes);
        }

        /// <summary>
        /// Creates an new intance of the <see cref="ECDHSharedKey"/> structure with the provided shared key bytes.
        /// </summary>
        /// <param name="publicKeyBytes">The span of bytes of the public key.</param>
        public ECDHSharedKey(ReadOnlySpan<byte> keyBytes)
        {
            _key = new ECDHKey(keyBytes);
        }

        /// <summary>
        /// Calculates and creates an ECDH shared key from the specified private and public key.
        /// </summary>
        /// <param name="privateKey">The self private key bytes.</param>
        /// <param name="publicKey">The other party public key bytes.</param>
        public static ECDHSharedKey Create(in ECDHPrivateKey privateKey, in ECDHPublicKey publicKey)
        {
            var _keyBytes = ECDHAlgorithmService.GetSharedSecretKey(publicKey, privateKey);
            return new ECDHSharedKey(_keyBytes);
        }

        /// <summary>
        /// Gets the shared key bytes.
        /// </summary>
        public byte[] GetBytes() => _key.GetBytes();

        /// <summary>
        /// Gets an string representation of this <see cref="ECDHSharedKey"/>.
        /// </summary>
        public override string ToString() => $"[ECDHSharedKey 0x{StaticOperations.ToHexString(GetBytes())}]";
    }
}
