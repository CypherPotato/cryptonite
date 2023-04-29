using Cryptonite.ECDH.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptonite.ECDH
{
    public struct ECDHSharedKey : IECDHKey
    {
        private byte[] _keyBytes;

        internal ECDHSharedKey(ECDHPrivateKey secretKey, ECDHPublicKey peerPublicKey)
        {
            _keyBytes = ECDHAlgorithmService.GetSharedSecretKey(peerPublicKey._keyBytes, secretKey._keyBytes);
        }

        public byte[] GetBytes() => _keyBytes;
        public override string ToString() => BitConverter.ToString(_keyBytes)!.Replace("-", "").ToLower();
    }
}
