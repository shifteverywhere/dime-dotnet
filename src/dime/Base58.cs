//
//  Base58.cs
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace ShiftEverywhere.DiME
{
	public static class Base58
	{
        #region -- PUBLIC INTERFACE --

		public static string Encode(byte[] data)
		{
			if (data == null || data.Length == 0) { throw new ArgumentNullException(nameof(data), "Key to encode must not be null or of zero length."); }
			byte[] bytes = Utility.Combine(data, GenerateChecksum(data));
			// First the byte array to encode must be converted to a BigInteger
			BigInteger bigInt = 0;
			for (int i = 0; i < bytes.Length; i++)
			{
				bigInt = bigInt * 256 + bytes[i];
			}
			// Second, the BigInter is encoded as a Base58 string
			string base58 = "";
			while (bigInt > 0)
			{
				int remainder = (int)(bigInt % 58);
				bigInt /= 58;
				base58 = IndexTable[remainder] + base58;
			}
			// All leading zeros are exchanged to ones
			for (int i = 0; i < bytes.Length && bytes[i] == 0; i++)
			{
				base58 = '1' + base58;
			}
			return base58;
		}


		public static byte[] Decode(string encoded)
		{
            if (encoded == null || encoded.Length == 0) { throw new ArgumentNullException(nameof(encoded), "Encoded string to decode must not be null or of zero length."); }
			// Decode Base58 string to BigInteger 
			BigInteger bigInt = 0;
			for (int index = 0; index < encoded.Length; index++)
			{
				int digit = IndexTable.IndexOf(encoded[index]); //Slow
				if (digit < 0) { throw new FormatException($"Illegal character ({encoded[index]}) found at index: {index}."); }
				bigInt = bigInt * 58 + digit;
			}
			// Encode BigInteger to byte[]
			// Leading zero bytes get encoded as leading `1` characters
			int leadingZeroCount = encoded.TakeWhile(c => c == '1').Count();
			var leadingZeros = Enumerable.Repeat((byte)0, leadingZeroCount);
			var bytesWithoutLeadingZeros =
				bigInt.ToByteArray()
				.Reverse()// to big endian
				.SkipWhile(b => b == 0);//strip sign byte
			var bytes = leadingZeros.Concat(bytesWithoutLeadingZeros).ToArray();

            byte[] stipped = Utility.SubArray(bytes, 0, bytes.Length - CHECKSUM_SIZE);
            byte[] checksum = Utility.SubArray(bytes, bytes.Length - CHECKSUM_SIZE);
			if (!VerifyChecksum(stipped, checksum)) { throw new FormatException("Invalid checksum."); }
			return stipped;
		}

        #endregion

        #region -- PRIVATE --

   		private const int CHECKSUM_SIZE = 4;
		private const string IndexTable = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

		private static byte[] GenerateChecksum(byte[] data)
		{
			SHA256 sha256 = new SHA256Managed();
			byte[] hash1 = sha256.ComputeHash(data);
			byte[] hash2 = sha256.ComputeHash(hash1);
			var result = new byte[CHECKSUM_SIZE];
			Buffer.BlockCopy(hash2, 0, result, 0, result.Length);
			return result;
		}

        private static bool VerifyChecksum(byte[] bytes, byte[] checksum)
		{
			return checksum.SequenceEqual(GenerateChecksum(bytes));
		}

        #endregion

	}
}