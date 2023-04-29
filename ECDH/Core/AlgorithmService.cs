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
        private const int PrivateKeySizeInBytes = 32;
        private const int PublicKeySizeInBytes = 32;
        private const int SharedKeySizeInBytes = 32;

        public static byte[] GetRandomPrivateKey()
        {
            var privateKey = new byte[PrivateKeySizeInBytes];
            RandomNumberGenerator.Create().GetBytes(privateKey);
            ClampOperation.Clamp(s: privateKey, offset: 0);
            return privateKey;
        }

        public static byte[] GetPublicKey(byte[] secretKey)
        {
            if (secretKey == null) throw new ArgumentNullException(nameof(secretKey));
            if (secretKey.Length != PrivateKeySizeInBytes) throw new ArgumentException($"{nameof(secretKey)} must be {PrivateKeySizeInBytes}");

            var publicKey = new byte[PrivateKeySizeInBytes];
            Array.Copy(sourceArray: secretKey, destinationArray: publicKey, length: PrivateKeySizeInBytes);

            ClampOperation.Clamp(s: publicKey);

            var a = GroupElementsOperations.ScalarMultiplicationBase(a: publicKey); // To MontgomeryX

            var tempX = FieldElementOperations.Add(f: ref a.Z, g: ref a.Y); //Get X
            var tempZ = FieldElementOperations.Sub(f: ref a.Z, g: ref a.Y);
            tempZ = FieldElementOperations.Invert(z: ref tempZ); //Get Z

            // Obtains the Public Key                                                        
            var publicKeyFieldElement = FieldElementOperations.Multiplication(f: ref tempX, g: ref tempZ); //X*Z       
            FieldElementOperations.ToBytes(s: publicKey, h: ref publicKeyFieldElement);
            return publicKey;
        }

        public static byte[] GetSharedSecretKey(byte[] peerPublicKey, byte[] privateKey)
        {
            if (peerPublicKey == null) throw new ArgumentNullException(nameof(peerPublicKey));
            if (peerPublicKey.Length != PublicKeySizeInBytes) throw new ArgumentException($"{nameof(peerPublicKey)} must be {PublicKeySizeInBytes}");

            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));
            if (privateKey.Length != PrivateKeySizeInBytes) throw new ArgumentException($"{nameof(privateKey)} must be {PrivateKeySizeInBytes}");

            //Resolve SharedSecret Key using the Montgomery Elliptical Curve Operations...
            var sharedSecretKey = MontgomeryOperations.ScalarMultiplication(
                n: privateKey,
                p: peerPublicKey,
                qSize: SharedKeySizeInBytes);

            //hashes like the NaCl paper says instead i.e. HSalsa(x,0)
            sharedSecretKey = Salsa20.HSalsa20(key: sharedSecretKey);

            return sharedSecretKey;
        }
    }
}
