using Cryptonite.ECDH.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptonite.ECDH
{
    /// <summary>
    /// Represents an ECDH public key.
    /// </summary>
    public readonly struct ECDHPublicKey
    {
        internal readonly byte[] _keyBytes;

        /// <summary>
        /// Creates an <see cref="ECDHPublicKey"/> from the specified <see cref="ECDHPrivateKey"/>.
        /// </summary>
        /// <param name="privateKey">The ECDH private key.</param>
        public static ECDHPublicKey FromPrivateKey(in ECDHPrivateKey privateKey)
        {
            var pubpk = ECDHAlgorithmService.GetPublicKey(privateKey._keyBytes);
            return new ECDHPublicKey(pubpk);
        }

        /// <summary>
        /// Creates an new intance of the <see cref="ECDHPublicKey"/> structure with the provided public key bytes.
        /// </summary>
        /// <param name="publicKeyBytes">The array of bytes of the public key.</param>
        public ECDHPublicKey(byte[] publicKeyBytes)
        {
            if (publicKeyBytes.Length != 32) throw new ArgumentException("Public key byte length should be exact 32 bytes-long.");
            _keyBytes = publicKeyBytes;
        }

        /// <summary>
        /// Creates an new intance of the <see cref="ECDHPublicKey"/> structure with the provided public key bytes.
        /// </summary>
        /// <param name="publicKeyBytes">The span of bytes of the public key.</param>
        public ECDHPublicKey(ReadOnlyMemory<byte> publicKeyBytes)
        {
            if (publicKeyBytes.Length != 32) throw new ArgumentException("Public key byte length should be exact 32 bytes-long.");
            _keyBytes = publicKeyBytes.ToArray();
        }

        /// <summary>
        /// Gets an string representation of this <see cref="ECDHPrivateKey"/>.
        /// </summary>
        /// <returns>An hex string containing this private key bytes.</returns>
        public override string ToString() => string.Join("", GetBytes().Select(b => b.ToString("x2")));

        /// <summary>
        /// Gets the public key bytes.
        /// </summary>
        public byte[] GetBytes() => _keyBytes.ToArray();
    }
}
