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
    /// </summary>
    /// <param name="payload">The payload to encrypt and attach to the message, must not be null and of length >= 1.</param>
    /// <param name="issuerKey">This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.</param>
    /// <param name="audienceKey">This is the key of the audience of the message, must be of type EXCHANGE, must not be null.</param>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public void SetPayload(byte[] payload, Key issuerKey, Key audienceKey)
    {
        ThrowIfSigned();
        if (payload == null || payload.Length == 0) { throw new ArgumentException("Unable to set payload, payload must not be null or empty."); }
        if (issuerKey == null) { throw new ArgumentNullException(nameof(issuerKey), "Unable to encrypt, issuer key must not be null."); }
        if (audienceKey == null) { throw new ArgumentNullException(nameof(audienceKey), "Unable to encrypt, audience key may not be null."); }
        var sharedKey = issuerKey.GenerateSharedSecret(audienceKey, new List<KeyCapability>() { KeyCapability.Encrypt });
        SetPayload(Dime.Crypto.Encrypt(payload, sharedKey));
    }

    /// <summary>
    /// Returns the decrypted message payload, if it is able to decrypt it.
    /// </summary>
    /// <param name="issuerKey">This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.</param>
    /// <param name="audienceKey">This is the key of the audience of the message, must be of type EXCHANGE, must not be null.</param>
    /// <returns>The message payload.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    /// <exception cref="ArgumentException"></exception>
    public byte[] GetPayload(Key issuerKey, Key audienceKey)
    {
        if (issuerKey == null) { throw new ArgumentNullException(nameof(issuerKey), "Unable to decrypt, issuer key may not be null."); }
        if (audienceKey == null) { throw new ArgumentNullException(nameof(audienceKey), "Unable to decrypt, audience key may not be null."); }
        var sharedKey = issuerKey.GenerateSharedSecret(audienceKey, new List<KeyCapability>() { KeyCapability.Encrypt });
        return Dime.Crypto.Decrypt(GetPayload(), sharedKey);
    }

    /// <inheritdoc />
    public override string GenerateThumbprint(string? suiteName = null)
    {
        if (!IsSigned) throw new InvalidOperationException("Unable to generate thumbprint, message not signed.");
        return base.GenerateThumbprint(suiteName);
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
    
    private static readonly List<Claim> AllowedClaims = new() { Claim.Amb, Claim.Aud, Claim.Ctx, Claim.Exp, Claim.Iat, Claim.Iss, Claim.Kid, Claim.Mim, Claim.Mtd, Claim.Sub, Claim.Sys, Claim.Uid };
    private new const int MinimumNbrComponents = 4;

    #endregion

}