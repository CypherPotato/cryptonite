using Cryptonite.ECDH.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptonite.ECDH
{
    public struct ECDHPublicKey : IECDHKey
    {
        internal byte[] _keyBytes;

        public ECDHPublicKey(byte[] publicKeyBytes)
        {
            if (publicKeyBytes.Length != 32) throw new ArgumentException("Public key byte length should be exact 32 bytes-long.");
            _keyBytes = publicKeyBytes;
        }

        public ECDHPublicKey(ECDHPrivateKey derivePrivateKey)
        {
            _keyBytes = ECDHAlgorithmService.GetPublicKey(derivePrivateKey._keyBytes);
        }

        public override string ToString() => BitConverter.ToString(_keyBytes)!.Replace("-", "").ToLower();

        public byte[] GetBytes() => _keyBytes;
    }
}
