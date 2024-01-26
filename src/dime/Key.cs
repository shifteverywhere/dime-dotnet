//
//  Key.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
// 
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;
using DiME.Capability;

namespace DiME;

/// <summary>
/// Represents cryptographic keys. This may be keys for signing and verifying other Di:ME items and envelopes, used
/// for encryption purposes, or when exchanging shared keys between entities.
/// </summary>
public class Key: Item
{
    #region -- PUBLIC --
        
    /// <summary>
    ///  The item header for DiME Key items.
    /// </summary>
    public const string ItemHeader = "KEY";
    /// <summary>
    /// Returns the header of the DiME item.
    /// </summary>
    public override string Header => ItemHeader;
    /// <summary>
    /// The cryptographic suite used to generate they key.
    /// </summary>
    public string CryptoSuiteName
    {
        get
        {
            if (_suiteName is not null) return _suiteName;
            if (KeyBytes(Claim.Key) is null)
                KeyBytes(Claim.Pub);
            return _suiteName;
        }
    }
    /// <summary>
    /// The secret part of the key. This part should never be stored or transmitted in plain text.
    /// </summary>
    public string Secret => Claims()?.Get<string>(Claim.Key);
    /// <summary>
    /// The public part of the key. This part may be stored or transmitted in plain text.
    /// </summary>
    public string Public => Claims()?.Get<string>(Claim.Pub);
    /// <summary>
    /// Returns the raw byte array of the requested key. Valid claims to request are Claim.KEY and Claim.PUB.
    /// </summary>
    /// <param name="claim">The key, expressed as a claim, to request bytes of.</param>
    /// <returns> The raw byte array of the key, null if none exists.</returns>
    /// <exception cref="ArgumentException"></exception>
    public byte[] KeyBytes(Claim claim)
    {
        switch (claim)
        {
            case Claim.Key:
            {
                if (_secretBytes == null)
                    DecodeKey(Claims()?.Get<string>(Claim.Key), Claim.Key);
                return _secretBytes;
            }
            case Claim.Pub:
            {
                if (_publicBytes == null)
                    DecodeKey(Claims()?.Get<string>(Claim.Pub), Claim.Pub);
                return _publicBytes;
            }
            default:
                throw new ArgumentException($"Invalid claim for key provided: {claim}.");
        }
    }
    /// <summary>
    /// Returns the unique name of this key. This name will be included in any signatures produced.
    /// </summary>
    public string Name => Dime.Crypto.GenerateKeyName(this);
    /// <summary>
    /// A list of cryptographic uses that the key may perform.
    /// </summary>
    public ReadOnlyCollection<KeyCapability> Capabilities
    {
        get
        {
            if (_capabilities is not null) return _capabilities;
            var caps = Claims()?.Get<List<string>>(Claim.Cap);
            if (caps is not null)
            {
                _capabilities = caps.ConvertAll(input =>
                {
                    Enum.TryParse(input, true, out KeyCapability cap);
                    return cap;
                }).AsReadOnly();
            }
            else
            {
                // This may be legacy
                KeyBytes(Claim.Pub);
                KeyBytes(Claim.Key);
                _capabilities = new ReadOnlyCollection<KeyCapability>(new List<KeyCapability>(){ Key.KeyCapabilityFromKeyType(Type) });
            }
            return _capabilities;
        }
    }
    /// <summary>
    /// Returns if the item is marked as legacy (compatible with Dime format before official version 1). 
    /// </summary>
    public override bool IsLegacy
    {
        get
        {
            // Get the keys (if needed) to check if this is legacy
            KeyBytes(Claim.Pub);
            KeyBytes(Claim.Key);
            return base.IsLegacy;
        }
        internal set => base.IsLegacy = value;
    }

    /// <summary>
    /// Indicates if a key has a specific cryptographic capability.
    /// </summary>
    /// <param name="capability">The capability to test for.</param>
    /// <returns>True if key supports the capability, false otherwise.</returns>
    public bool HasCapability(KeyCapability capability)
    {
        return Capabilities.Contains(capability);
    }
        
    /// <summary>
    /// Empty constructor, not to be used. Required for Generics.
    /// </summary>
    public Key() { }

    /// <summary>
    /// Constructor to create a key instance from raw key byte-arrays. This is intended to be used by cryptographic
    /// suite implementations to create keys from generated byte-arrays.
    /// </summary>
    /// <param name="capabilities">The capabilities of the created key.</param>
    /// <param name="rawKey">The raw secret/private key as a byte-array.</param>
    /// <param name="rawPub">The raw public key as a byte-array.</param>
    /// <param name="suiteName">The name of the cryptographic suite that was used to create the key.</param>
    public Key(List<KeyCapability> capabilities, byte[] rawKey, byte[] rawPub, string suiteName)
    : this(Guid.NewGuid(), capabilities, rawKey, rawPub, suiteName) { }
    
    /// <summary>
    /// Will generate a new Key for a specific cryptographic capability.
    /// </summary>
    /// <param name="capability">The capability of the key.</param>
    /// <returns>A newly generated key.</returns>
    public static Key Generate(KeyCapability capability)
    {
        return Generate(new List<KeyCapability>() { capability }, Dime.NoExpiration, null, null);
    }
        
    /// <summary>
    /// Will generate a new Key for a specific cryptographic capabilities and attach a specified context.
    /// </summary>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="context">The context to attach to the key, may be null.</param>
    /// <returns>A newly generated key.</returns>
    public static Key Generate(List<KeyCapability> capabilities, string context = null)
    {
        return Generate(capabilities, Dime.NoExpiration, null, context);
    }

    /// <summary>
    /// Will generate a new Key for a specific cryptographic usage, an expiration date, and the identifier of the
    /// issuer. Abiding to the expiration date is application specific as the key will continue to function after
    /// the expiration date. Providing -1 as validFor will skip setting an expiration date. The specified context
    /// will be attached to the generated key. The cryptographic suite specified will be used when generating the
    /// key.
    /// </summary>
    /// <param name="capabilities">The capabilities of the key.</param>
    /// <param name="validFor">The number of seconds that the key should be valid for, from the time of issuing.</param>
    /// <param name="issuerId">The identifier of the issuer (creator) of the key, may be null.</param>
    /// <param name="context">The context to attach to the key, may be null.</param>
    /// <param name="suiteName">The name of the cryptographic suite to use, if null, then the default suite will be used.</param>
    /// <returns>A newly generated key.</returns>
    /// <exception cref="ArgumentException"></exception>
    public static Key Generate(List<KeyCapability> capabilities, long validFor = Dime.NoExpiration, Guid? issuerId = null, string context = null, string suiteName = null)
    {
        if (context is {Length: > Dime.MaxContextLength}) { throw new ArgumentException("Context must not be longer than " + Dime.MaxContextLength + "."); }
        var key = Dime.Crypto.GenerateKey(capabilities, suiteName ?? Dime.Crypto.DefaultSuiteName);
        if (validFor != Dime.NoExpiration)
            key.SetClaimValue(Claim.Exp, key.GetClaim<DateTime>(Claim.Iat).AddSeconds(validFor));
        key.SetClaimValue(Claim.Iss, issuerId);
        key.SetClaimValue(Claim.Ctx, context);
        return key;
    }

    /// <summary>
    /// Will create a copy of a key with only the public part left. This should be used when transmitting a key to
    /// another entity, when the receiving entity only needs the public part.
    /// </summary>
    /// <returns>A new instance of the key with only the public part.</returns>
    public Key PublicCopy()
    {
        var copyKey = new Key(Capabilities.ToList(), null, Public, _suiteName);
        if (HasClaim(Claim.Uid)) copyKey.SetClaimValue(Claim.Uid, GetClaim<Guid>(Claim.Uid));
        if (HasClaim(Claim.Iat)) copyKey.SetClaimValue(Claim.Iat, GetClaim<DateTime>(Claim.Iat));
        if (HasClaim(Claim.Exp)) copyKey.SetClaimValue(Claim.Exp, GetClaim<DateTime>(Claim.Exp));
        if (HasClaim(Claim.Iss)) copyKey.SetClaimValue(Claim.Iss, GetClaim<Guid>(Claim.Iss));
        if (HasClaim(Claim.Ctx)) copyKey.SetClaimValue(Claim.Ctx, GetClaim<string>(Claim.Ctx));
        return copyKey;
    }

    /// <summary>
    /// Generates a shared secret from the current key and another provided key. Both keys must have key usage
    /// 'Exchange' specified.
    /// </summary>
    /// <param name="key">The other key to use with the key exchange (generation of shared key).</param>
    /// <param name="capabilities">The requested capabilities of the generated shared key, usually 'Encrypt'.</param>
    /// <returns>The generated shared key.</returns>
    public Key GenerateSharedSecret(Key key, List<KeyCapability> capabilities)
    {
        return Dime.Crypto.GenerateSharedSecret(this, key, capabilities);
    }

    /// <summary>
    /// Converts the item to legacy (compatible with earlier version of the Dime specification, before version 1)
    /// </summary>
    public override void ConvertToLegacy()
    {
        if (IsLegacy) return;
        ConvertKeyToLegacy(this, Capabilities[0], Claim.Key);
        ConvertKeyToLegacy(this, Capabilities[0], Claim.Pub);
        base.ConvertToLegacy();
    }

    #endregion

    #region -- INTERNAL --

    internal Key(Guid id, List<KeyCapability> capabilities, byte[] rawKey, byte[] rawPub, string suiteName)
    {
        SetClaimValue(Claim.Uid, id);
        SetClaimValue(Claim.Iat, Utility.CreateDateTime());
        _suiteName = suiteName ?? Dime.Crypto.DefaultSuiteName;
        SetClaimValue(Claim.Cap, capabilities.ConvertAll(keyUse => keyUse.ToString().ToLower()));
        if (rawKey is not null)
            SetClaimValue(Claim.Key, PackageKey(_suiteName, Dime.Crypto.EncodeKeyBytes(rawKey, Claim.Key, _suiteName)));
        if (rawPub is not null)
            SetClaimValue(Claim.Pub, PackageKey(_suiteName, Dime.Crypto.EncodeKeyBytes(rawPub, Claim.Pub, _suiteName)));
    }

    internal Key(List<KeyCapability> capabilities, string key, string pub, string suiteName)
    {
        _suiteName = suiteName ?? Dime.Crypto.DefaultSuiteName;
        SetClaimValue(Claim.Cap, capabilities.ConvertAll(keyUse => keyUse.ToString().ToLower()));
        if (key is not null)
            SetClaimValue(Claim.Key, key);
        if (pub is not null)
            SetClaimValue(Claim.Pub, pub);
    }

    internal Key(List<KeyCapability> capabilities, string key, Claim claim)
    {
        SetClaimValue(Claim.Cap, capabilities.ConvertAll(keyUse => keyUse.ToString().ToLower()));
        SetClaimValue(claim, key);
    }
        
    #endregion

    # region -- PROTECTED --

    /// <inheritdoc />
    protected override bool AllowedToSetClaimDirectly(Claim claim)
    {
        return AllowedClaims.Contains(claim);
    }
    
    /// <inheritdoc />
    protected override void CustomDecoding(List<string> components)
    {
        if (components.Count > MinimumNbrComponents + 1)
            throw new FormatException($"More components in item than expected, got {components.Count}, expected {MinimumNbrComponents + 1}");
        IsSigned = components.Count > MinimumNbrComponents;
    }

    #endregion

    #region -- PRIVATE --

    private static readonly List<Claim> AllowedClaims = new() { Claim.Amb, Claim.Aud, Claim.Cmn, Claim.Ctx, Claim.Exp, Claim.Iat, Claim.Iss, Claim.Isu, Claim.Kid, Claim.Mtd, Claim.Sub, Claim.Sys, Claim.Uid };
    private const int CryptoSuiteIndex = 0;
    private const int EncodedKeyIndex = 1;
    private const int LegacyKeyHeaderSize = 6;
    private string _suiteName;
    private ReadOnlyCollection<KeyCapability> _capabilities;
    private byte[] _secretBytes;
    private byte[] _publicBytes;
    private KeyType? _type;
 
    [Obsolete("Obsolete method, remove once legacy is not supported anymore.")]
    private static KeyType GetKeyType(IReadOnlyList<byte> key)
    {
        switch ((AlgorithmFamily)Enum.ToObject(typeof(AlgorithmFamily), key[1]))
        {
            case AlgorithmFamily.Aead:
                return KeyType.Encryption;
            case AlgorithmFamily.Ecdh:
                return KeyType.Exchange;
            case AlgorithmFamily.Eddsa:
                return KeyType.Identity;
            case AlgorithmFamily.Hash:
                return KeyType.Authentication;
            case AlgorithmFamily.Undefined:
            default:
                return KeyType.Undefined;
        }
    }
        
    private static string PackageKey(string suiteName, string encodedKey)
    {
        return $"{suiteName}{Dime.ComponentDelimiter}{encodedKey}";
    }
        
    private void DecodeKey(string encoded, Claim claim)
    {
        if (encoded is null || encoded.Length == 0) { return; }
        var components = encoded.Split(new[] { Dime.ComponentDelimiter });
        string suiteName;
        var legacyKey = false;
        if (components.Length == 2)
            suiteName = components[CryptoSuiteIndex];
        else
        {
            // This will be treated as legacy
            suiteName = "STN";
            legacyKey = true;
        }
        if (_suiteName is null)
            _suiteName = suiteName;
        else if (!_suiteName.Equals(suiteName))
        {
            var otherKeyPart = claim == Claim.Key ? GetClaim<string>(Claim.Pub) : GetClaim<string>(Claim.Key);
            if (otherKeyPart != null)
                throw new InvalidOperationException($"Unable to decode key, public and secret keys generated using different cryptographic suites: {_suiteName} and {suiteName}.");
        }
        byte[] rawKey;
        if (!legacyKey)
            rawKey = Dime.Crypto.DecodeKeyBytes(components[EncodedKeyIndex], claim, suiteName);
        else
        {
            // This is a legacy key
            var decoded = Dime.Crypto.DecodeKeyBytes(encoded, claim, suiteName);
            rawKey = Utility.SubArray(decoded, LegacyKeyHeaderSize);
            _type = GetKeyType(decoded);
        }
        switch (claim)
        {
            case Claim.Key:
                _secretBytes = rawKey;
                break;
            case Claim.Pub:
                _publicBytes = rawKey;
                break;
            default:
                throw new ArgumentException($"Unable to decode key, invalid claim provided for key: {claim}.");
        }
        IsLegacy = legacyKey;
    }
        
    private static KeyCapability KeyCapabilityFromKeyType(KeyType type)
    {
        switch (type)
        {
            case KeyType.Identity:
                return KeyCapability.Sign;
            case KeyType.Exchange:
                return KeyCapability.Exchange;
            case KeyType.Encryption:
                return KeyCapability.Encrypt;
            case KeyType.Undefined:
            case KeyType.Authentication:
            default:
                throw new ArgumentOutOfRangeException(nameof(type), type, null);
        }
    }
        
    /// <summary>
    /// Returns the type of the key. The type determines what the key may be used for, this since it is also
    /// closely associated with the cryptographic algorithm the key is generated for.
    /// </summary>
    [Obsolete("This method is no longer used, use Key.Capability instead.")]
    private KeyType Type { 
        get
        {
            if (_type is not null) return (KeyType) _type;
            if (IsLegacy)
            {
                var key = Claims()?.Get<string>(Claim.Key);
                if (key is null)
                {
                    key = Claims()?.Get<string>(Claim.Pub);
                    DecodeKey(key, Claim.Pub);
                }
                else
                    DecodeKey(key, Claim.Key);
            }
            else
            {
                if (HasCapability(KeyCapability.Sign))
                    _type = KeyType.Identity;
                else if (HasCapability(KeyCapability.Exchange))
                    _type = KeyType.Exchange;
                else if (HasCapability(KeyCapability.Encrypt))
                    _type = KeyType.Encryption;
            }
            Debug.Assert(_type != null, "Unexpected error, unable to get legacy type of key.");
            return (KeyType) _type;
        }
    }
    
    private static void ConvertKeyToLegacy(Item item, KeyCapability capability, Claim claim)
    {
        var key = item.Claims()?.Get<string>(claim);
        if (key is null) { return; }
        var header = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
        var components = key.Split(Dime.ComponentDelimiter);
        if (components.Length == 1) return; // This is already a legacy key
        var rawKey = Dime.Crypto.DecodeKeyBytes(components[1], claim, components[0]);
        var legacyKey = Utility.Combine(header, rawKey);
        legacyKey[1] = capability == KeyCapability.Encrypt ? (byte) 0x10 : capability == KeyCapability.Exchange ? (byte) 0x40 : (byte) 0x80;
        legacyKey[2] = capability == KeyCapability.Exchange ? (byte) 0x02 : (byte) 0x01;
        if (claim == Claim.Pub)
            legacyKey[3] = 0x01;
        else if (capability == KeyCapability.Encrypt)
            legacyKey[3] = 0x02;
        item.Claims()?.Put(claim, Base58.Encode(legacyKey));
    }
    
    #endregion
}