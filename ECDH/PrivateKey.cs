using Cryptonite.ECDH.Core;
using System.Security.Cryptography.X509Certificates;

namespace Cryptonite.ECDH
{
    public struct ECDHPrivateKey : IECDHKey
    {
        internal ECDHPublicKey? _publKey;
        internal byte[] _keyBytes;

        public ECDHPrivateKey()
        {
            _keyBytes = ECDHAlgorithmService.GetRandomPrivateKey();
        }

        public ECDHPrivateKey(byte[] privateKeyBytes)
        {
            if (privateKeyBytes.Length != 32) throw new ArgumentException("Private key byte length should be exact 32 bytes-long.");
            _keyBytes = privateKeyBytes;
        }

        public byte[] GetBytes() => _keyBytes;

        public ECDHPublicKey GetPublicKey()
        {
            if (!_publKey.HasValue)
            {
                _publKey = new ECDHPublicKey(this);
            }
            return _publKey.Value;
        }

        public ECDHSharedKey GetSharedKey(ECDHPublicKey peerPublicKey)
        {
            return new ECDHSharedKey(this, peerPublicKey);
        }

        public override string ToString() => BitConverter.ToString(_keyBytes)!.Replace("-", "").ToLower();
    }
}