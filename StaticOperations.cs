using Cryptonite.ECDH;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace Cryptonite
{
    public static class StaticOperations
    {
        public static bool TimingSafeEqual(IECDHKey a, IECDHKey b) => TimingSafeEqual(a.GetBytes(), b.GetBytes());

        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool TimingSafeEqual(byte[] a, byte[] b)
        {
            bool result = true;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                result &= a[i] == b[i];
            }
            return result;
        }

        public static byte[] XorGate(byte[] a, byte[] b)
        {
            if (a.Length != b.Length) throw new Exception("The arrays must be the same size.");

            byte[] outputKey = new byte[a.Length];

            for (int i = 0; i < a.Length; i++)
            {
                outputKey[i] = (byte)(a[i] ^ b[i]);
            }

            return outputKey;
        }

        public static byte[] Pbkdf2Derive(IECDHKey key, int length, PBKDF2Parameters parameters) => Pbkdf2Derive(key.GetBytes(), length, parameters);

        public static byte[] Pbkdf2Derive(byte[] key, int length, PBKDF2Parameters parameters)
        {
            return Rfc2898DeriveBytes.Pbkdf2(
                 key,
                 parameters.Salt,
                 parameters.Iterations,
                 parameters.HashAlgorithm,
                 length
             );
        }
    }

    public class PBKDF2Parameters
    {
        public byte[] Salt { get; set; }
        public int Iterations { get; set; }
        public HashAlgorithmName HashAlgorithm { get; set; }

        public PBKDF2Parameters()
        {
            this.HashAlgorithm = HashAlgorithmName.SHA256;
            this.Salt = new byte[] { };
            this.Iterations = 10000;
        }
    }
}