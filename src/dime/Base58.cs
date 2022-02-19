//
//  Base58.cs
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Security.Cryptography;

namespace DiME
{

	///<summary>
	/// Encodes and decodes byte arrays and strings to and from base 58. This is mainly used to encode/decode keys.
	///</summary>
	public static class Base58
	{

        #region -- PUBLIC INTERFACE --

        ///<summary>
        /// Encodes a byte array and an optional prefix to base 58. The prefix will be added to the front of the data
        /// array.
        ///</summary>
		///<param name="data">The main byte array to encode.</param>
		///<param name="prefix">A byte array that will be added to the front of data before encoding.</param>
		///<returns>Base 58 encoded string</returns>
		public static string Encode(byte[] data, byte[] prefix) {
			if (data is not {Length: > 0}) return null;
			var length = (prefix != null) ? prefix.Length + data.Length : data.Length;
			var bytes = new byte[length + Base58.NbrChecksumBytes];
			if (prefix != null) {
				Buffer.BlockCopy(prefix, 0, bytes, 0, prefix.Length);
				Buffer.BlockCopy(data, 0, bytes, prefix.Length, data.Length);
			} else {
				Buffer.BlockCopy(data, 0, bytes, 0, data.Length);
			}

			var checksum = Base58.DoubleHash(bytes, length);
			Buffer.BlockCopy(checksum, 0, bytes, length, Base58.NbrChecksumBytes);
			// Count leading zeros, to know where to start
			var start = bytes.TakeWhile(aByte => aByte == 0).Count();

			var builder = new StringBuilder();
			for(var index = start; index < bytes.Length;) {
				builder.Insert(0, IndexTable[CalculateIndex(bytes, index, 256, 58)]);
				if (bytes[index] == 0) {
					++index;
				}
			}
			while (start > 0) {
				builder.Insert(0, '1');
				start--;
			}
			return builder.ToString();
		}

        /// <summary>
        /// Decodes a base 58 string to a byte array.
        /// </summary>
        /// <param name="encoded">The base 58 string that should be decoded.</param>
        /// <returns>A decoded byte array.</returns>
		public static byte[] Decode(string encoded) {
			if (encoded.Length == 0) {
            	return Array.Empty<byte>();
        	}
			byte[] input58 = new byte[encoded.Length];
			for (int i = 0; i < encoded.Length; ++i) {
				char c = encoded[i];
				int digit = (c < 128) ? Base58.ReverseTable[c] : -1;
				input58[i] = (byte) digit;
			}
			// Count leading zeros to know how many to restore
			var start = 0;
			while (start < input58.Length && input58[start] == 0) {
				++start;
			}
			var decoded = new byte[encoded.Length];
			var position = decoded.Length;
			for (var index = start; index < input58.Length; ) {
				decoded[--position] = CalculateIndex(input58, index, 58, 256);
				if (input58[index] == 0) {
					++index;
				}
			}
			while (position < decoded.Length && decoded[position] == 0) {
				++position;
			}

			var result = Utility.SubArray(decoded, position - start);
			var data = Utility.SubArray(result, 0, result.Length - Base58.NbrChecksumBytes);
			var checksum = Utility.SubArray(result, result.Length - Base58.NbrChecksumBytes);
			var actualChecksum = Utility.SubArray(Base58.DoubleHash(data, result.Length - Base58.NbrChecksumBytes), 0, Base58.NbrChecksumBytes);
			return Base58.Compare(checksum, actualChecksum) ? data : Array.Empty<byte>();
		}

		#endregion

		static Base58() 
		{
			Array.Fill(Base58.ReverseTable, -1);
			for (var i = 0; i < Base58.IndexTable.Length; i++) {
				Base58.ReverseTable[Base58.IndexTable[i]] = i;
			}
		}

		#region -- PRIVATE --

    	private const int NbrChecksumBytes = 4;
		private static readonly char[] IndexTable = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".ToCharArray();
		private static readonly int[] ReverseTable = new int[128];

		private static byte[] DoubleHash(byte[] message, int length) {
			var toHash = Utility.SubArray(message, 0, length);
			SHA256 sha256 = SHA256.Create();
			return sha256.ComputeHash(sha256.ComputeHash(toHash));
		}

		private static byte CalculateIndex(byte[] bytes, int position, int aBase, int divisor) {
			var remainder = 0;
			for (var i = position; i < bytes.Length; i++) {
				var digit = bytes[i] & 255;
				var temp = remainder * aBase + digit;
				bytes[i] = (byte)(temp / divisor);
				remainder = temp % divisor;
			}
			return (byte)remainder;
    	}

		private static bool Compare(IReadOnlyCollection<byte> array1, IReadOnlyList<byte> array2)
		{
			if (array1.Count != array2.Count)
				return false;
			return !array1.Where((t, index) => t != array2[index]).Any();
		}

		#endregion

	}

}