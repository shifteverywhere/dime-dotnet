//
//  Signature.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//

using System;
using System.Collections.Generic;
using System.Text;

namespace DiME;

/// <summary>
/// Encapsulates a digital signature. A signature consists of two components, a key name and the actual signature. The
/// key name is used to identify the key that may be used to verify the signature.
/// </summary>
public class Signature
{
    #region -- PUBLIC --
    
    /// <summary>
    /// The raw bytes of the signature.
    /// </summary>
    public byte[] Bytes { get; private set; }
    /// <summary>
    /// The key name for the key that may be used to verify the signature.
    /// </summary>
    public string Name { get; private set;  }

    /// <summary>
    /// Indicates if the signature is of legacy format.
    /// </summary>
    public bool IsLegacy => Name == null;
    
    /// <summary>
    /// Default constructor. If the name is omitted (null passed) then the signature will be considered as of legacy
    /// format.
    /// </summary>
    /// <param name="bytes">The raw bytes of a signature.</param>
    /// <param name="name">The key name.</param>
    public Signature(byte[] bytes, string name)
    {
        Bytes = bytes;
        Name = name;
    }

    /// <summary>
    /// Decodes a string of encoded signatures and returns a list of Signature instances.
    /// </summary>
    /// <param name="encoded">The string of encoded signatures.</param>
    /// <returns>A list of Signature instances.</returns>
    /// <exception cref="ArgumentException"></exception>
    public static List<Signature> FromEncoded(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            throw new ArgumentException("Encoded list of signatures must not be null or empty.", nameof(encoded));
        var signatures = new List<Signature>();
        var decoded = Encoding.UTF8.GetString(Utility.FromBase64(encoded));
        var items = decoded.Split(new[] { Dime.SectionDelimiter });
        foreach (var combined in items)
        {
            var components = combined.Split(new[] {Dime.ComponentDelimiter});
            if (components.Length == 1)
            {
                // This is a legacy signature
                signatures.Add(new Signature(Utility.FromBase64(encoded), null));
                break; // No need to continue, legacy only supports one signature per item
            }
            else
            {
                try
                {
                    signatures.Add(new Signature(Utility.FromHex(components[IndexSignature]), components[IndexKeyName]));
                }
                catch (Exception)
                {
                    // This is a legacy signature
                    signatures.Add(new Signature(Utility.FromBase64(encoded), null));
                    break; // No need to continue, legacy only supports one signature per item
                }
            }
        }
        return signatures;
    }

    /// <summary>
    /// Encodes a provided list of Signature instances to a string, used when exporting Dime items.
    /// </summary>
    /// <param name="signatures">A list of Signature instances to encode.</param>
    /// <returns>An encoded string.</returns>
    public static string ToEncoded(List<Signature> signatures)
    {
        var builder = new StringBuilder();
        var isLegacy = signatures[0].Name == null;
        foreach (var signature in signatures)
        {
            if (builder.Length > 0)
                builder.Append(Dime.SectionDelimiter);
            signature.ToEncoded(builder);
        }
        return isLegacy ? builder.ToString() : Utility.ToBase64(builder.ToString());
    }

    /// <summary>
    /// Finds a signature that matches a provided key name, if one is to be found.
    /// </summary>
    /// <param name="name">The key name to look for.</param>
    /// <param name="signatures">A list of Signature instances to look in.</param>
    /// <returns>The found signature, or null if none could be found.</returns>
    public static Signature Find(string name, List<Signature> signatures)
    {
        return signatures?.Find(signature => signature.Name.Equals(name));
    }
    
    #endregion
    
    #region -- PRIVATE --

    private const int IndexKeyName = 0;
    private const int IndexSignature = 1;

    private void ToEncoded(StringBuilder builder)
    {
        if (IsLegacy)
            builder.Append(Utility.ToBase64(Bytes));
        else
            builder.Append(Name)
                .Append(Dime.ComponentDelimiter)
                .Append(Utility.ToHex(Bytes));
    }

    #endregion

}