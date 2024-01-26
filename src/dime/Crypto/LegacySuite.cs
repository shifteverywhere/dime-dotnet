//
//  LegacySuite.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//

using System;
using ASodium;

namespace DiME.Crypto;

/// <summary>
/// Implements the legacy suits used in previous specifications of DiME, i.e. STN and DSC.
/// </summary>
[Obsolete("Will be removed in future versions, use NaCl instead (default).")]
internal class LegacySuite: NaClSuite
{

    #region -- PUBLIC --
    
    /// <summary>
    /// Default constructor.
    /// </summary>
    /// <param name="name">The name of the suite.</param>
    public LegacySuite(string name) : base(name) { }

    /// <inheritdoc />
    public override byte[] GenerateSignature(Item item, Key key)
    {
        var signature = SodiumPublicKeyAuth.SignDetached(item.RawEncoded(false), key.KeyBytes(Claim.Key));
        return signature;
    }

    /// <inheritdoc />
    public override bool VerifySignature(Item item, byte[] signature, Key key)
    {
        return SodiumPublicKeyAuth.VerifyDetached(signature, item.RawEncoded(false), key.KeyBytes(Claim.Pub));
    }

    /// <inheritdoc />
    public override string EncodeKeyBytes(byte[] rawKey, Claim claim)
    {
        return _suiteName.Equals(LegacyStnSuite) ? Base58.Encode(rawKey) : base.EncodeKeyBytes(rawKey, claim);
    }

    /// <inheritdoc />
    public override byte[] DecodeKeyBytes(string encodedKey, Claim claim)
    {
        return _suiteName.Equals(LegacyStnSuite) ? Base58.Decode(encodedKey) : base.DecodeKeyBytes(encodedKey, claim);
    }
    
    #endregion

    #region -- INTERNAL --

    internal const string LegacyDscSuite = "DSC"; // Base64 encoding
    internal const string LegacyStnSuite = "STN"; // Base58 encoding    

    #endregion
    
    #region --- PRIVATE ---
    
    //private string _suiteName;
    
    #endregion
}