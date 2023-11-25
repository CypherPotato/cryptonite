using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptonite;

public static partial class StaticOperations
{
    public static Span<byte> Concat(Span<byte> in1, Span<byte> in2, Span<byte> in3, Span<byte> in4, Span<byte> in5, Span<byte> in6, Span<byte> in7, Span<byte> in8)
    {
        Span<byte> result = new Span<byte>(new byte[in1.Length + in2.Length + in3.Length + in4.Length + in5.Length + in6.Length + in7.Length + in8.Length]);
        Copy(in1, ref result, 0);
        Copy(in2, ref result, in1.Length);
        Copy(in3, ref result, in1.Length + in2.Length);
        Copy(in4, ref result, in1.Length + in2.Length + in3.Length);
        Copy(in5, ref result, in1.Length + in2.Length + in3.Length + in4.Length);
        Copy(in6, ref result, in1.Length + in2.Length + in3.Length + in4.Length + in5.Length);
        Copy(in7, ref result, in1.Length + in2.Length + in3.Length + in4.Length + in5.Length + in6.Length);
        Copy(in8, ref result, in1.Length + in2.Length + in3.Length + in4.Length + in5.Length + in6.Length + in7.Length);
        return result;
    }

    public static Span<byte> Concat(Span<byte> in1, Span<byte> in2, Span<byte> in3, Span<byte> in4, Span<byte> in5, Span<byte> in6, Span<byte> in7)
    {
        Span<byte> result = new Span<byte>(new byte[in1.Length + in2.Length + in3.Length + in4.Length + in5.Length + in6.Length + in7.Length]);
        Copy(in1, ref result, 0);
        Copy(in2, ref result, in1.Length);
        Copy(in3, ref result, in1.Length + in2.Length);
        Copy(in4, ref result, in1.Length + in2.Length + in3.Length);
        Copy(in5, ref result, in1.Length + in2.Length + in3.Length + in4.Length);
        Copy(in6, ref result, in1.Length + in2.Length + in3.Length + in4.Length + in5.Length);
        Copy(in7, ref result, in1.Length + in2.Length + in3.Length + in4.Length + in5.Length + in6.Length);
        return result;
    }

    public static Span<byte> Concat(Span<byte> in1, Span<byte> in2, Span<byte> in3, Span<byte> in4, Span<byte> in5, Span<byte> in6)
    {
        Span<byte> result = new Span<byte>(new byte[in1.Length + in2.Length + in3.Length + in4.Length + in5.Length + in6.Length]);
        Copy(in1, ref result, 0);
        Copy(in2, ref result, in1.Length);
        Copy(in3, ref result, in1.Length + in2.Length);
        Copy(in4, ref result, in1.Length + in2.Length + in3.Length);
        Copy(in5, ref result, in1.Length + in2.Length + in3.Length + in4.Length);
        Copy(in6, ref result, in1.Length + in2.Length + in3.Length + in4.Length + in5.Length);
        return result;
    }

    public static Span<byte> Concat(Span<byte> in1, Span<byte> in2, Span<byte> in3, Span<byte> in4, Span<byte> in5)
    {
        Span<byte> result = new Span<byte>(new byte[in1.Length + in2.Length + in3.Length + in4.Length + in5.Length]);
        Copy(in1, ref result, 0);
        Copy(in2, ref result, in1.Length);
        Copy(in3, ref result, in1.Length + in2.Length);
        Copy(in4, ref result, in1.Length + in2.Length + in3.Length);
        Copy(in5, ref result, in1.Length + in2.Length + in3.Length + in4.Length);
        return result;
    }

    public static Span<byte> Concat(Span<byte> in1, Span<byte> in2, Span<byte> in3, Span<byte> in4)
    {
        Span<byte> result = new Span<byte>(new byte[in1.Length + in2.Length + in3.Length + in4.Length]);
        Copy(in1, ref result, 0);
        Copy(in2, ref result, in1.Length);
        Copy(in3, ref result, in1.Length + in2.Length);
        Copy(in4, ref result, in1.Length + in2.Length + in3.Length);
        return result;
    }

    public static Span<byte> Concat(Span<byte> in1, Span<byte> in2, Span<byte> in3)
    {
        Span<byte> result = new Span<byte>(new byte[in1.Length + in2.Length + in3.Length]);
        Copy(in1, ref result, 0);
        Copy(in2, ref result, in1.Length);
        Copy(in3, ref result, in1.Length + in2.Length);
        return result;
    }

    public static Span<byte> Concat(Span<byte> in1, Span<byte> in2)
    {
        Span<byte> result = new Span<byte>(new byte[in1.Length + in2.Length]);
        Copy(in1, ref result, 0);
        Copy(in2, ref result, in1.Length);
        return result;
    }
}
