//
//  Data.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright (c) 2024 Shift Everywhere AB. All rights reserved.
//

#nullable enable
using System;
using System.Collections.Generic;
using System.Text;
using DiME.KeyRing;

namespace DiME;

/// <summary>
/// DiME item that carries a data payload. The payload may be any data.
/// </summary>
public class Data: Item
{
    #region -- PUBLIC --
    
    /// <summary>
    /// The item header for DiME Data items.
    /// </summary>
    public const string ItemHeader = "DAT";
    /// <summary>
    /// Returns the header of the DiME item.
    /// </summary>
    public override string Header => ItemHeader;

    /// <summary>
    /// Empty constructor, not to be used. Required for generics.
    /// </summary>
    public Data() { }
    
    /// <summary>
    /// Creates a new Data instance with the provided parameters.
    /// </summary>
    /// <param name="issuerId">The identifier of the issuer.</param>
    /// <param name="validFor">Number of seconds the data item should be valid, if -1 is provided, then it will never expire.</param>
    /// <param name="context">The context to attach to the data item, may be null.</param>
    public Data(Guid issuerId, long validFor = Dime.NoExpiration, string? context = null)
    {
        if (context is {Length: > Dime.MaxContextLength})
            throw new ArgumentException($"Context must not be longer than {Dime.MaxContextLength}.", nameof(context));
        var claims = Claims();
        claims?.Put(Claim.Uid, Guid.NewGuid());
        claims?.Put(Claim.Iss, issuerId);
        var iat = Utility.CreateDateTime();
        claims?.Put(Claim.Iat, iat);
        DateTime? exp = validFor != Dime.NoExpiration ? iat.AddSeconds(validFor) : null;
        claims?.Put(Claim.Exp, exp);
        claims?.Put(Claim.Ctx, context);
    }
    
    /// <summary>
    /// Sets the data payload of the item.
    /// </summary>
    /// <param name="payload">The payload to set.</param>
    /// <param name="mimeType">The MIME type of the payload, may be null.</param>
    public void SetPayload(byte[] payload, string? mimeType = null) 
    {
        ThrowIfSigned();
        Payload = Utility.ToBase64(payload);
        Claims()?.Put(Claim.Mim, mimeType);
    }
    
    /// <summary>
    /// 
    /// </summary>
    /// <returns></returns>
    public byte[] GetPayload() {
        return Utility.FromBase64(Payload);
    }
    
    /// <summary>
    /// Will sign the data item with the proved key. The Key instance must contain a secret key and have use 'Sign'.
    /// </summary>
    /// <param name="signingKey">The key to sign the item with.</param>
    /// <exception cref="InvalidOperationException"></exception>
    public override void Sign(Key signingKey)
    {
        if (Payload == null) 
            throw new InvalidOperationException("Unable to sign message, no payload added.");
        base.Sign(signingKey);
    }
    
    /// <summary>
    /// Verifies the signature of the data item using a provided key and verifies a linked item from the proved item.
    /// To verify correctly the linkedItem must be the original item that the data item was linked to.
    /// </summary>
    /// <param name="key">The key to used to verify the signature.</param>
    /// <param name="linkedItems">Items that are linked to the item being verified.</param>
    /// <exception cref="InvalidOperationException"></exception>
    /// <exception cref="FormatException"></exception>
    public override IntegrityState Verify(Key? key = null, List<Item>? linkedItems = null) { 
        if (string.IsNullOrEmpty(Payload)) 
            throw new InvalidOperationException("Unable to verify message, no payload added.");
        return base.Verify(key, linkedItems);
    }
    
    #endregion

    #region -- PROTECTED --

    /// <summary>
    /// The Base64 encoded payload attached to the item.
    /// </summary>
    protected string? Payload;

    /// <inheritdoc />
    protected override bool AllowedToSetClaimDirectly(Claim claim)
    {
        return AllowedClaims.Contains(claim);
    }
    
    /// <inheritdoc />
    protected override void CustomDecoding(List<string> components)
    {
        if (components.Count > MaximumNbrComponents)
            throw new FormatException(
                $"More components in item than expected, got {components.Count}, expected maximum {MaximumNbrComponents}.");
        Payload = components[ComponentsPayloadIndex];
        IsSigned = components.Count == MaximumNbrComponents;
    }

    /// <inheritdoc />
    protected override void CustomEncoding(StringBuilder builder)
    {
        base.CustomEncoding(builder);
        builder.Append(Dime.ComponentDelimiter);
        builder.Append(Payload);
    }

    /// <inheritdoc />
    protected override int GetMinNbrOfComponents()
    {
        return MinimumNbrComponents;
    }

    #endregion

    #region --PRIVATE --

    private static readonly List<Claim> AllowedClaims = new () { Claim.Amb, Claim.Aud, Claim.Cmn, Claim.Ctx, Claim.Exp, Claim.Iat, Claim.Iss, Claim.Isu, Claim.Kid, Claim.Mim, Claim.Mtd, Claim.Sub, Claim.Sys, Claim.Uid };
    private new const int MinimumNbrComponents = 3;
    private const int MaximumNbrComponents = MinimumNbrComponents + 1;
    private const int ComponentsPayloadIndex = 2;
    
    #endregion

}