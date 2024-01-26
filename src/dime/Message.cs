//
//  Message.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
// 
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
#nullable enable
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using DiME.Capability;

namespace DiME;

/// <summary>
/// A class that can be used to create secure and integrity protected messages, that can be sent to entities, who
/// may verify the integrity and trust of the message. Messages may also be end-to-end encrypted to protect the
/// confidentiality of the message payload.
/// </summary>
public class Message: Data
{
    #region -- PUBLIC DATA MEMBERS --
        
    /// <summary>
    ///  The item header for DiME Message items.
    /// </summary>
    public new const string ItemHeader = "MSG";
    /// <summary>
    /// Returns the header of the DiME item.
    /// </summary>
    public override string Header => ItemHeader;
    /// <summary>
    /// A public key that was included in the message. Normally this public key was used for a key exchange where
    /// the shared key was used to encrypt the payload. This is optional.
    /// </summary>
    public Key? PublicKey
    {
        get
        {
            if (_publicKey is not null) return _publicKey;
            _publicKey = new Key(new List<KeyCapability>() {KeyCapability.Exchange}, GetClaim<string>(Claim.Pub),
                Claim.Pub);
            return _publicKey;
        }
        set
        {
            ThrowIfSigned();
            _publicKey = value;
            if (value != null)
                SetClaimValue(Claim.Pub, value.Public);
        }
    }
    private Key? _publicKey;

    #endregion
        
    #region -- PUBLIC CONSTRUCTORS --

    /// <summary>
    /// Empty constructor, not to be used. Required for Generics.
    /// </summary>
    public Message() { }

    /// <summary>
    /// Creates a message from a specified issuer (sender) and an expiration date.
    /// </summary>
    /// <param name="issuerId">The issuer identifier.</param>
    /// <param name="validFor">The number of seconds that the message should be valid for, from the time of issuing.</param>
    /// <param name="context">The context to attach to the message, may be null.</param>
    public Message(Guid issuerId, long validFor = Dime.NoExpiration, string? context = null): this(null, issuerId, validFor, context) { }

    /// <summary>
    /// Creates a message to a specified audience (receiver) from a specified issuer (sender), with an expiration
    /// date and a context. The context may be anything and may be used for application specific purposes.
    /// </summary>
    /// <param name="audienceId">The audience identifier. Providing -1 as validFor will skip setting an expiration
    /// date.</param>
    /// <param name="issuerId">The issuer identifier.</param>
    /// <param name="validFor">The number of seconds that the message should be valid for, from the time of issuing.</param>
    /// <param name="context">The context to attach to the message, may be null.</param>
    /// <exception cref="ArgumentException"></exception>
    public Message(Guid? audienceId, Guid issuerId, long validFor = Dime.NoExpiration, string? context = null)
    {
        if (context is {Length: > Dime.MaxContextLength}) { throw new ArgumentException("Context must not be longer than " + Dime.MaxContextLength + "."); }
        var iat = Utility.CreateDateTime();
        DateTime? exp = validFor != -1 ? iat.AddSeconds(validFor) : null;
        var claims = Claims();
        claims?.Put(Claim.Uid, Guid.NewGuid());
        claims?.Put(Claim.Aud, audienceId);
        claims?.Put(Claim.Iss, issuerId);
        claims?.Put(Claim.Iat, iat);
        claims?.Put(Claim.Exp, exp);
        claims?.Put(Claim.Ctx, context);
    }

    #endregion
        
    #region -- PUBLIC INTERFACE --
   
    /// <summary>
    /// Will encrypt and attach a payload using a shared encryption key between the issuer and audience of a message.
    /// The two keys provided must not be null and only one must contain a secret (private) key, the order does not matter.
    /// </summary>
    /// <param name="payload">The payload to encrypt and attach to the message, must not be null and of length 1 or longer.</param>
    /// <param name="firstKey">The first key to use, must have capability EXCHANGE, must not be null.</param>
    /// <param name="secondKey">The second key to use, must have capability EXCHANGE, must not be null.</param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public void SetPayload(byte[] payload, Key firstKey, Key secondKey)
    {
        ThrowIfSigned();
        if (payload == null || payload.Length == 0) { throw new ArgumentException("Unable to set payload, payload must not be null or empty."); }
        if (firstKey == null) { throw new ArgumentNullException(nameof(firstKey), "Unable to set payload, both keys must be of a non-null value."); }
        if (secondKey == null) { throw new ArgumentNullException(nameof(secondKey), "Unable to set payload, both keys must be of a non-null value."); }
        if (firstKey.Secret != null && secondKey.Secret != null) { throw new InvalidOperationException("Unable to set payload, both keys must not contain a secret (private) key."); }
        var primaryKey = firstKey.Secret != null ? firstKey : secondKey;
        var secondaryKey = secondKey.Secret == null ? secondKey : firstKey;
        var sharedKey = primaryKey.GenerateSharedSecret(secondaryKey, new List<KeyCapability>() { KeyCapability.Encrypt });
        SetPayload(Dime.Crypto.Encrypt(payload, sharedKey));
    }

    /// <summary>
    /// Will encrypt and attach a payload using the private key. The provided key may either have the capability
    /// Exchange or Encrypt. If Exchange is used, then a second key will be generated and then used to generate a shared
    /// encryption key with the provided key. The public key of the generated EXCHANGE key will be set in the "pub"
    /// claim, but also returned. If a key with capability ENCRYPT is used, then the payload will be encrypted with this
    /// key. This key will then be returned. The unique id of the encryption key will be set in the key id ("kid") claim.
    /// </summary>
    /// <param name="payload"></param>
    /// <param name="key"></param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public Key SetPayload(byte[] payload, Key key)
    {
        if (key == null) { throw new ArgumentNullException(nameof(key), "Unable to set payload, key must not be null."); }
        if (key.HasCapability(KeyCapability.Exchange))
        {
            if (key.Secret != null) { throw new ArgumentException("Unable to set payload, key should not contain a secret (private) key.", nameof(key)); }
            var firstKey = Key.Generate(KeyCapability.Exchange);
            SetPayload(payload, firstKey, key);
            PublicKey = firstKey.PublicCopy();
            return firstKey;
        }
        if (!key.HasCapability(KeyCapability.Encrypt)) throw new InvalidOperationException("Unable to set payload, key must have the capability Exchange or Encrypt.");
        SetPayload(Dime.Crypto.Encrypt(payload, key));
        PutClaim(Claim.Kid, key.GetClaim<Guid>(Claim.Uid));
        return key;
    }

    /// <summary>
    /// Returns the decrypted message payload, if it is able to decrypt it. Two keys must be provided, where only one of
    /// the keys may contain a secret (private), the order does not matter. The keys provided must be the same as when
    /// used SetPayload(byte[], Key, Key) or equivalent, although it may be the opposite pair of public and
    /// public/secret.
    /// </summary>
    /// <param name="firstKey">The first key to use, must be of type Exchange, must not be null.</param>
    /// <param name="secondKey">The second key to use, must be of type Exchange, must not be null.</param>
    /// <returns>The message payload.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public byte[] GetPayload(Key firstKey, Key secondKey)
    {
        if (firstKey == null) { throw new ArgumentNullException(nameof(firstKey), "Unable to get payload, both keys must be of a non-null value."); }
        if (secondKey == null) { throw new ArgumentNullException(nameof(secondKey), "Unable to get payload, both keys must be of a non-null value."); }
        if (firstKey.Secret != null && secondKey.Secret != null) { throw new InvalidOperationException("Unable to get payload, both keys must not contain a secret (private) key."); }
        var primaryKey = firstKey.Secret != null ? firstKey : secondKey;
        var secondaryKey = secondKey.Secret == null ? secondKey : firstKey;
        try
        {
            var sharedKey =
                secondaryKey.GenerateSharedSecret(primaryKey, new List<KeyCapability>() {KeyCapability.Encrypt});
            return Dime.Crypto.Decrypt(GetPayload(), sharedKey);
        }
        catch (CryptographicException) { /* ignored */ }
        var newSharedKey = primaryKey.GenerateSharedSecret(secondaryKey, new List<KeyCapability>() { KeyCapability.Encrypt });
        return Dime.Crypto.Decrypt(GetPayload(), newSharedKey);
    }

    /// <summary>
    /// Returns the decrypted message payload, if it is able to decrypt it. The provided key may either have the
    /// capability Exchange or Encrypt. If Exchange is used, then the "pub" claim will be used as a source for the
    /// second exchange key to use when generating a shared encryption key. If the key has capability Encrypt, then the
    /// payload will be decrypted using the provided key directly.
    /// </summary>
    /// <param name="key">A key to either use for generating a shared key (Exchange) or decrypting the message directly (Encrypt).</param>
    /// <returns>The decrypted message payload.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="InvalidOperationException"></exception>
    public byte[] GetPayload(Key key)
    {
        if (key == null) { throw new ArgumentNullException(nameof(key), "Unable to get payload, key must not be null."); }
        if (key.HasCapability(KeyCapability.Exchange))
        {
            if (GetClaim<string>(Claim.Pub) == null || PublicKey == null) throw new InvalidOperationException("Unable to get payload, no public key attached to message.");
            return GetPayload(PublicKey, key);
        }
        if (!key.HasCapability(KeyCapability.Encrypt)) throw new InvalidOperationException("Unable to get payload, key must have the capability Exchange or Encrypt.");
        return Dime.Crypto.Decrypt(GetPayload(), key);
    }

    #endregion
    
    # region -- INTERNAL --
    
    internal override string ForExport()
    {
        if (!IsSigned) throw new InvalidOperationException("Unable to encode item, must be signed first.");
        return base.ForExport();
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
        base.CustomDecoding(components);
        IsSigned = true; // Messages are always signed
    }

    /// <inheritdoc />
    protected override int GetMinNbrOfComponents()
    {
        return MinimumNbrComponents;
    }

    #endregion

    #region -- PRIVATE --
    
    private static readonly List<Claim> AllowedClaims = new() { Claim.Amb, Claim.Aud, Claim.Ctx, Claim.Exp, Claim.Iat, Claim.Iss, Claim.Isu, Claim.Kid, Claim.Mim, Claim.Mtd, Claim.Sub, Claim.Sys, Claim.Uid };
    private new const int MinimumNbrComponents = 4;

    #endregion

}