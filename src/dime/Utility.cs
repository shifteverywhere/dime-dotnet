//
//  Utility.cs
//  DiME - Date Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Security.Cryptography;
using System.Xml;

namespace DiME;

/// <summary>
/// Utility support methods.
/// </summary>
public static class Utility
{

    private static readonly RandomNumberGenerator Rng = RandomNumberGenerator.Create();
        
    /// <summary>
    /// Will generates random bytes.
    /// </summary>
    /// <param name="size">The number of bytes to generate.</param>
    /// <returns>A byte array with the generated bytes.</returns>
    public static byte[] RandomBytes(int size)
    {
        var value = new byte[size];
        Rng.GetBytes(value);
        return value;
    }

    /// <summary>
    /// Encode a byte array as a hexadecimal string.
    /// </summary>
    /// <param name="bytes">Byte array to encode.</param>
    /// <returns>Hexadecimal string.</returns>
    public static string ToHex(byte[] bytes)
    {
        var hex = new StringBuilder(bytes.Length * 2);
        foreach (var b in bytes)
            hex.Append($"{b:x2}");
        return hex.ToString();
    }

    /// <summary>
    /// Decodes a hexadecimal string to a byte array.
    /// </summary>
    /// <param name="str">The string to decode.</param>
    /// <returns>Decoded string.</returns>
    public static byte[] FromHex(string str) {
        if (str.Length % 2 == 1)
            throw new Exception("The binary key cannot have an odd number of digits");
        var arr = new byte[str.Length >> 1];
        for (var i = 0; i < str.Length >> 1; ++i)
            arr[i] = (byte)((GetHexVal(str[i << 1]) << 4) + (GetHexVal(str[(i << 1) + 1])));
        return arr;
    }

    private static int GetHexVal(char hex) {
        var val = (int)hex;
        //For uppercase A-F letters:
        //return val - (val < 58 ? 48 : 55);
        //For lowercase a-f letters:
        return val - (val < 58 ? 48 : 87);
        //Or the two combined, but a bit slower:
        //return val - (val < 58 ? 48 : (val < 97 ? 55 : 87));
    }
    

    /// <summary>
    /// Encode a byte array as a base 64 string.
    /// </summary>
    /// <param name="bytes">Byte array to encode.</param>
    /// <returns>Base 64 encoded string.</returns>
    public static string ToBase64(byte[] bytes)
    {
        return Convert.ToBase64String(bytes).Trim('=');
    }

    /// <summary>
    /// Encode a string as base 64.
    /// </summary>
    /// <param name="str">The string to encode.</param>
    /// <returns>Base 64 encoded string.</returns>
    public static string ToBase64(string str)
    {
        return ToBase64(Encoding.UTF8.GetBytes(str));
    }

    /// <summary>
    /// Decode a base 64 encoded string.
    /// </summary>
    /// <param name="base64">String to decode.</param>
    /// <returns>Decoded byte array.</returns>
    public static byte[] FromBase64(String base64)
    {
        var str = base64;
        str = str.Replace('_', '/').Replace('-', '+');
        var padding = base64.Length % 4;
        if (padding > 1)
        {
            str += padding == 2 ? "==" : "=";
        }
        return Convert.FromBase64String(str);
    }

    /// <summary>
    /// Combine two byte arrays.
    /// </summary>
    /// <param name="first">First byte array.</param>
    /// <param name="second">Second byte array.</param>
    /// <returns>First + second combined.</returns>
    public static byte[] Combine(byte[] first, byte[] second)   
    {
        var bytes = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, bytes, 0, first.Length);
        Buffer.BlockCopy(second, 0, bytes, first.Length, second.Length);
        return bytes;
    }

    /// <summary>
    /// Extract a sub-array from a byte array.
    /// </summary>
    /// <param name="array">The original byte array.</param>
    /// <param name="start">The start position in of the sub-array in the original array.</param>
    /// <param name="length">The length of the sub-array.</param>
    /// <returns>The extracted sub-array.</returns>
    public static byte[] SubArray(byte[] array, int start, int length)
    {
        var bytes = new byte[length];
        Buffer.BlockCopy(array, start, bytes, 0, length);
        return bytes;
    }

    /// <summary>
    /// Extract a sub-array from a byte array.
    /// </summary>
    /// <param name="array">The original byte array.</param>
    /// <param name="start">The start position in of the sub-array in the original array.</param>
    /// <returns>The extracted sub-array.</returns>
    public static byte[] SubArray(byte[] array, int start)
    {
        return SubArray(array, start, array.Length - start);
    }

    /// <summary>
    /// Prefixes a byte to a byte array.
    /// </summary>
    /// <param name="prefix">The byte to prefix.</param>
    /// <param name="array">The byte array to prefix to.</param>
    /// <returns>A byte array with a prefix.</returns>
    public static byte[] Prefix(byte prefix, byte[] array)
    {
        var bytes = new byte[array.Length + 1];
        array.CopyTo(bytes, 1);
        bytes[0] = prefix;
        return bytes;
    }

    /// <summary>
    /// Create a DateTime instance that, if the global time modifier is set, will modify the time accordingly.
    /// If no modifier is set, then the current local time, in UTC, will be captured.
    /// </summary>
    /// <returns></returns>
    public static DateTime CreateDateTime()
    {
        var now =  Dime.OverrideTime ?? DateTime.UtcNow;
        var modifier = Dime.TimeModifier;
        return modifier != 0L ? now.AddSeconds(modifier) : now;
    }
    
    /// <summary>
    /// Format as a RFC 3339 date.
    /// </summary>
    /// <param name="date">The date to format.</param>
    /// <returns>A string with a RFC 3339 formatted date.</returns>
    public static string ToTimestamp(DateTime date)
    {
        return XmlConvert.ToString(date, XmlDateTimeSerializationMode.Utc);
    }

    /// <summary>
    /// Parse RFC 3339 to a DateTime object.
    /// </summary>
    /// <param name="timestamp">The date to parse.</param>
    /// <returns>A DateTime object.</returns>
    public static DateTime FromTimestamp(string timestamp)  
    {
        return DateTime.Parse(timestamp).ToUniversalTime();
    }

    /// <summary>
    /// Will, if Dime.GracePeriod returns a value different from 0, compare two DateTime instances using a grace period.
    /// A lower and upper boundary will be calculated from the base time given, the size of this period will be based on
    /// the  grace period. The result given back will be equal to DateTime.CompareTo(DateTime).
    /// If no grace is set (0), then the two Instant objects will be compared directly.
    /// </summary>
    /// <param name="baseTime">The base time to compare a second DateTime instance with.</param>
    /// <param name="otherTime">The Instant instance to compare against the given base time.</param>
    /// <returns>Negative if less, positive is greater, or 0 if the same or within the grace period.</returns>
    public static int GracefulDateTimeCompare(DateTime? baseTime, DateTime? otherTime)
    {
        if (baseTime is null || otherTime is null) return 0;
        var gracePeriod = Dime.GracePeriod;
        if (gracePeriod == 0L)
            return baseTime.Value.CompareTo(otherTime.Value);
        var lower = baseTime.Value.AddSeconds(-gracePeriod);
        var lowerResult = lower.CompareTo(otherTime);
        var upper = baseTime.Value.AddSeconds(gracePeriod);
        var upperResult = upper.CompareTo(otherTime);
        return lowerResult == upperResult ? lowerResult : 0;
    }

}