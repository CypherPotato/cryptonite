using Cryptonite.ECDH.Core.Op;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Cryptonite.ECDH.Core
{
    internal static class ECDHAlgorithmService
    {
        internal const int PrivateKeySizeInBytes = 32;
        internal const int SharedKeySizeInBytes = 32;

        public static byte[] GetRandomPrivateKey()
        {
            var privateKey = new byte[PrivateKeySizeInBytes];
            RandomNumberGenerator.Create().GetBytes(privateKey);
            ClampOperation.Clamp(s: privateKey, offset: 0);
            return privateKey;
        }

        public static byte[] GetPublicKey(Span<byte> privateKey)
        {
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            if (privateKey.Length != PrivateKeySizeInBytes) throw new ArgumentException($"{nameof(privateKey)} must be {PrivateKeySizeInBytes}");

            Span<byte> publicKey = stackalloc byte[32];
            privateKey.CopyTo(publicKey);

            ClampOperation.Clamp(publicKey);

            var a = GroupElementsOperations.ScalarMultiplicationBase(publicKey); // To MontgomeryX

            var tempX = FieldElementOperations.Add(ref a.Z, ref a.Y); //Get X
            var tempZ = FieldElementOperations.Sub(ref a.Z, ref a.Y);
            tempZ = FieldElementOperations.Invert(ref tempZ); //Get Z

            // Obtains the Public Key
            var publicKeyFieldElement = FieldElementOperations.Multiplication(ref tempX, ref tempZ); //X*Z       
            FieldElementOperations.ToBytes(publicKey, ref publicKeyFieldElement);

            return publicKey.ToArray();
        }

        public static byte[] GetSharedSecretKey(in ECDHPublicKey peerPublicKey, in ECDHPrivateKey privateKey)
        {
            //Resolve SharedSecret Key using the Montgomery Elliptical Curve Operations...
            var sharedSecretKey = MontgomeryOperations.ScalarMultiplication(
                n: privateKey._key.GetBytes(),
                p: peerPublicKey._key.GetBytes(),
                qSize: SharedKeySizeInBytes);

            //hashes like the NaCl paper says instead i.e. HSalsa(x,0)
            sharedSecretKey = Salsa20.HSalsa20(key: sharedSecretKey);

            return sharedSecretKey.ToArray();
        }
    }
}
