using Cryptonite.ECDH;
using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Cryptonite
{
    /// <summary>
    /// Provides static, useful cryptographic functions.
    /// </summary>
    public static partial class StaticOperations
    {
        private static Random StringGenerationRandom = new Random();

        /// <summary>
        /// Compares whether the two spans are identical, in a timing-safe comparison, which does not return immediately in case of divergence.
        /// </summary>
        /// <param name="a">The first span.</param>
        /// <param name="b">The second span.</param>
        /// <returns></returns>
        [MethodImpl(MethodImplOptions.NoInlining | MethodImplOptions.NoOptimization)]
        public static bool TimingSafeEqual(Span<byte> a, Span<byte> b)
        {
            bool result = true;
            if (a.Length != b.Length) return false;
            for (int i = 0; i < a.Length; i++)
            {
                result &= a[i] == b[i];
            }
            return result;
        }

        /// <summary>
        /// Creates a fixed-size array from the input span and pads the excess with zeros.
        /// </summary>
        /// <param name="arr">The input array.</param>
        /// <param name="length">The new array size.</param>
        /// <param name="padFromLeft">Indicates whether the array should be filled from the left (true) or right.</param>
        public static byte[] PadZeros(Span<byte> arr, int length, bool padFromLeft = false)
        {
            int inputLength = arr.Length;

            if (inputLength > length) throw new InvalidOperationException("The input array length must be lower or equal than the padding length.");
            if (length < 0) throw new InvalidOperationException("Length must be non negative.");
            if (inputLength == length) return arr.ToArray();

            Span<byte> padObj = stackalloc byte[length];

            if (padFromLeft)
            {
                Copy(arr, ref padObj, length - arr.Length);
            }
            else
            {
                Copy(arr, ref padObj, 0);
            }

            return padObj.ToArray();
        }

        /// <summary>
        /// Copies data from A to B.
        /// </summary>
        /// <param name="from">The A span.</param>
        /// <param name="to">The B span.</param>
        /// <param name="index">The start index of the copy.</param>
        public static void Copy(Span<byte> from, ref Span<byte> to, int index)
        {
            for (int i = 0; i < from.Length; i++)
            {
                to[i + index] = from[i];
            }
        }

        /// <summary>
        /// Applies an XOR gate between two spans.
        /// </summary>
        /// <param name="from">The A span.</param>
        /// <param name="to">The B span.</param>
        public static byte[] XorGate(Span<byte> a, Span<byte> b)
        {
            if (a.Length != b.Length) throw new Exception("The arrays must be the same size.");

            Span<byte> outputKey = stackalloc byte[a.Length];

            for (int i = 0; i < a.Length; i++)
            {
                outputKey[i] = (byte)(a[i] ^ b[i]);
            }

            return outputKey.ToArray();
        }

        /// <summary>
        /// Applies an XOR gate between two spans modifying the original span.
        /// </summary>
        /// <param name="from">The A span.</param>
        /// <param name="to">The B span.</param>
        public static void RefXorGate(ref Span<byte> a, Span<byte> b)
        {
            if (a.Length != b.Length) throw new Exception("The arrays must be the same size.");
            for (int i = 0; i < a.Length; i++)
            {
                a[i] ^= b[i];
            }
        }

        /// <summary>
        /// Fills an span with cryptographically strong bytes.
        /// </summary>
        /// <param name="buffer">The output span.</param>
        public static void RefRandomSecureBytes(ref Span<byte> buffer)
        {
            RandomNumberGenerator.Create().GetBytes(buffer);
        }

        /// <summary>
        /// Gets an array of cryptographically strong bytes.
        /// </summary>
        /// <param name="length">The size of the array.</param>
        public static byte[] RandomSecureBytes(int length)
        {
            var bytes = new byte[length];
            RandomNumberGenerator.Create().GetBytes(bytes);
            return bytes;
        }

        /// <summary>
        /// Generates an random string with the specified length.
        /// </summary>
        /// <param name="length">The string length.</param>
        /// <param name="alphabet">Optional. The string which contains the letters which will be added to the final result.</param>
        /// <returns></returns>
        public static string RandomString(int length, string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789/;.,!@#$%")
        {
            return new string(alphabet.Select(c => alphabet[StringGenerationRandom.Next(alphabet.Length)]).Take(length).ToArray());
        }

        public static Span<byte> Pbkdf2Derive(Span<byte> key, int length, PBKDF2Parameters parameters)
        {
            ArgumentNullException.ThrowIfNull(nameof(parameters.Salt));

            return new Span<byte>(Rfc2898DeriveBytes.Pbkdf2(
                key,
                parameters.Salt,
                parameters.Iterations,
                parameters.HashAlgorithm,
                length
            ));
        }
    }

    public class PBKDF2Parameters
    {
        public byte[]? Salt { get; set; }
        public int Iterations { get; set; }
        public HashAlgorithmName HashAlgorithm { get; set; }

        public PBKDF2Parameters()
        {
            this.HashAlgorithm = HashAlgorithmName.SHA256;
            this.Iterations = 10000;
        }
    }
}