using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

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
                Copy(arr, padObj, length - arr.Length);
            }
            else
            {
                Copy(arr, padObj, 0);
            }

            return padObj.ToArray();
        }

        /// <summary>
        /// Copies data from A to B.
        /// </summary>
        /// <param name="from">The A span.</param>
        /// <param name="to">The B span.</param>
        /// <param name="index">The start index of the copy.</param>
        public static void Copy(Span<byte> from, Span<byte> to, int index)
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
        public static void RefXorGate(Span<byte> a, Span<byte> b)
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

        /// <summary>
        /// Reads the input byte array into an hex string.
        /// </summary>
        /// <param name="bytes">The input byte array.</param>
        public static string ToHexString(Span<byte> bytes)
        {
            StringBuilder sb = new StringBuilder(bytes.Length * 2);

            for (int i = 0; i < bytes.Length; i++)
            {
                sb.Append(bytes[i].ToString("x2"));
            }

            return sb.ToString();
        }

        /// <summary>
        /// Reads the input hex string into an byte array.
        /// </summary>
        /// <param name="hexString">The input hex string.</param>
        public static byte[] FromHexString(string hexString)
        {
            int GetHexVal(int val) => val - (val < 58 ? 48 : (val < 97 ? 55 : 87));

            if (hexString.Length % 2 == 1)
                throw new Exception("The hex string cannot have an odd number of digits.");

            byte[] arr = new byte[hexString.Length >> 1];

            for (int i = 0; i < hexString.Length >> 1; ++i)
            {
                arr[i] = (byte)((GetHexVal(hexString[i << 1]) << 4) + (GetHexVal(hexString[(i << 1) + 1])));
            }

            return arr;
        }
    }
}