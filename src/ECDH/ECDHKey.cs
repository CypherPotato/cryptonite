using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Cryptonite.ECDH;

/// <summary>
/// Represents an ECDH key.
/// </summary>
public readonly struct ECDHKey
{
    readonly byte byte1;
    readonly byte byte2;
    readonly byte byte3;
    readonly byte byte4;
    readonly byte byte5;
    readonly byte byte6;
    readonly byte byte7;
    readonly byte byte8;
    readonly byte byte9;
    readonly byte byte10;
    readonly byte byte11;
    readonly byte byte12;
    readonly byte byte13;
    readonly byte byte14;
    readonly byte byte15;
    readonly byte byte16;
    readonly byte byte17;
    readonly byte byte18;
    readonly byte byte19;
    readonly byte byte20;
    readonly byte byte21;
    readonly byte byte22;
    readonly byte byte23;
    readonly byte byte24;
    readonly byte byte25;
    readonly byte byte26;
    readonly byte byte27;
    readonly byte byte28;
    readonly byte byte29;
    readonly byte byte30;
    readonly byte byte31;
    readonly byte byte32;

    /// <summary>
    /// Creates an new instance of the <see cref="ECDHKey"/> struct.
    /// </summary>
    public ECDHKey(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != 32)
            throw new ArgumentException("The input buffer must contain exactly 32 bytes.");

        byte1 = bytes[0];
        byte2 = bytes[1];
        byte3 = bytes[2];
        byte4 = bytes[3];
        byte5 = bytes[4];
        byte6 = bytes[5];
        byte7 = bytes[6];
        byte8 = bytes[7];
        byte9 = bytes[8];
        byte10 = bytes[9];
        byte11 = bytes[10];
        byte12 = bytes[11];
        byte13 = bytes[12];
        byte14 = bytes[13];
        byte15 = bytes[14];
        byte16 = bytes[15];
        byte17 = bytes[16];
        byte18 = bytes[17];
        byte19 = bytes[18];
        byte20 = bytes[19];
        byte21 = bytes[20];
        byte22 = bytes[21];
        byte23 = bytes[22];
        byte24 = bytes[23];
        byte25 = bytes[24];
        byte26 = bytes[25];
        byte27 = bytes[26];
        byte28 = bytes[27];
        byte29 = bytes[28];
        byte30 = bytes[29];
        byte31 = bytes[30];
        byte32 = bytes[31];
    }

    /// <summary>
    /// Gets the current ECDH key bytes.
    /// </summary>
    public byte[] GetBytes()
    {
        return new byte[]
        {
            byte1, byte2, byte3, byte4, byte5, byte6, byte7, byte8,
            byte9, byte10, byte11, byte12, byte13, byte14, byte15, byte16,
            byte17, byte18, byte19, byte20, byte21, byte22, byte23, byte24,
            byte25, byte26, byte27, byte28, byte29, byte30, byte31, byte32
        };
    }
}
