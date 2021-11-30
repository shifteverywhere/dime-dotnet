//
//  Base58.cs
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Security.Cryptography;

namespace ShiftEverywhere.DiME
{

	public static class Base58
	{

        #region -- PUBLIC INTERFACE --

		public static String Encode(byte[] data, byte[] prefix) {
			if (data != null && data.Length > 0) {
            	int length = (prefix != null) ? prefix.Length + data.Length : data.Length;
            	byte[] bytes = new byte[length + Base58.NBR_CHECKSUM_BYTES];
            	if (prefix != null) {
					Buffer.BlockCopy(prefix, 0, bytes, 0, prefix.Length);
					Buffer.BlockCopy(data, 0, bytes, prefix.Length, data.Length);
            	} else {
					Buffer.BlockCopy(data, 0, bytes, 0, data.Length);
            	}

            byte[] checksum = Base58.DoubleHash(bytes, length);
			Buffer.BlockCopy(checksum, 0, bytes, length, Base58.NBR_CHECKSUM_BYTES);
            // Count leading zeros, to know where to start
            int start = 0;
			foreach (byte aByte in bytes)
			{
                if (aByte != 0) {
                    break;
                }
                start++;
			}

			StringBuilder builder = new StringBuilder();
            for(int index = start; index < bytes.Length;) {
				builder.Insert(0, _indexTable[CalculateIndex(bytes, index, 256, 58)]);
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
        return null;
		}

		public static byte[] Decode(string encoded) {
			if (encoded.Length == 0) {
            	return new byte[0];
        	}
			byte[] input58 = new byte[encoded.Length];
			for (int i = 0; i < encoded.Length; ++i) {
				char c = encoded[i];
				int digit = (c < 128) ? Base58._reverseTable[c] : -1;
				input58[i] = (byte) digit;
			}
			// Count leading zeros to know how many to restore
			int start = 0;
			while (start < input58.Length && input58[start] == 0) {
				++start;
			}
			byte[] decoded = new byte[encoded.Length];
			int position = decoded.Length;
			for (int index = start; index < input58.Length; ) {
				decoded[--position] = CalculateIndex(input58, index, 58, 256);
				if (input58[index] == 0) {
					++index;
				}
			}
			while (position < decoded.Length && decoded[position] == 0) {
				++position;
			}

			byte[] result = Utility.SubArray(decoded, position - start);
			byte[] data = Utility.SubArray(result, 0, result.Length - Base58.NBR_CHECKSUM_BYTES);
			byte[] checksum = Utility.SubArray(result, result.Length - Base58.NBR_CHECKSUM_BYTES);
			byte[] actualChecksum = Utility.SubArray(Base58.DoubleHash(data, result.Length - Base58.NBR_CHECKSUM_BYTES), 0, Base58.NBR_CHECKSUM_BYTES);
			if (Base58.Compare(checksum, actualChecksum)) {
				return data;
			}
			return null;
		}

		#endregion

		static Base58() 
		{
			Array.Fill(Base58._reverseTable, -1);
			for (int i = 0; i < Base58._indexTable.Length; i++) {
				Base58._reverseTable[Base58._indexTable[i]] = i;
			}
		}

		#region -- PRIVATE --

    	private const int NBR_CHECKSUM_BYTES = 4;
		public static readonly char[] _indexTable = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".ToCharArray();
		private static readonly int[] _reverseTable = new int[128];

		public static byte[] DoubleHash(byte[] message, int length) {
			byte[] toHash = Utility.SubArray(message, 0, length);
			SHA256 sha256 = new SHA256Managed();
			return sha256.ComputeHash(sha256.ComputeHash(toHash));
		}

		private static byte CalculateIndex(byte[] bytes, int position, int aBase, int divisor) {
			int remainder = 0;
			for (int i = position; i < bytes.Length; i++) {
				int digit = (int)bytes[i] & 255;
				int temp = remainder * aBase + digit;
				bytes[i] = (byte)(temp / divisor);
				remainder = temp % divisor;
			}
			return (byte)remainder;
    	}

		private static bool Compare(byte[] array1, byte[] array2)
		{
			if (array1.Length != array2.Length)
				return false;
			for (int index = 0; index< array1.Length; index++)
				if (array1[index] != array2[index])
					return false;
			return true;
		}

		#endregion

	}

}