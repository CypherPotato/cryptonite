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
        private readonly byte[] _keyBytes;

        /// <summary>
        /// Creates an new intance of the <see cref="ECDHSharedKey"/> structure with the provided shared key bytes.
        /// </summary>
        /// <param name="publicKeyBytes">The array of bytes of the public key.</param>
        public ECDHSharedKey(byte[] keyBytes)
        {
            if (keyBytes.Length != 32) throw new ArgumentException("Shared key byte length should be exact 32 bytes-long.");
            _keyBytes = keyBytes;
        }

        /// <summary>
        /// Creates an new intance of the <see cref="ECDHSharedKey"/> structure with the provided shared key bytes.
        /// </summary>
        /// <param name="publicKeyBytes">The span of bytes of the public key.</param>
        public ECDHSharedKey(ReadOnlyMemory<byte> keyBytes)
        {
            if (keyBytes.Length != 32) throw new ArgumentException("Shared key byte length should be exact 32 bytes-long.");
            _keyBytes = keyBytes.ToArray();
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
        public byte[] GetBytes() => _keyBytes;

        /// <summary>
        /// Gets an string representation of this <see cref="ECDHSharedKey"/>.
        /// </summary>
        public override string ToString() => string.Join("", GetBytes().Select(b => b.ToString("x2")));
    }
}
