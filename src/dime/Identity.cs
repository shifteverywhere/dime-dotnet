//
//  Identity.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//

#nullable enable
using System;
using System.Text;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using DiME.Capability;
using DiME.KeyRing;

namespace DiME;

///<summary>
/// Represents a digital identity of an entity. Can be self-signed or signed by a trusted identity (and thus be part
/// of a trust chain.
///</summary>
public class Identity: Item
{
    #region -- PUBLIC --

    /// <summary>
    ///  The item header for DiME Identity items.
    /// </summary>
    public const string ItemHeader = "ID";
    /// <summary>
    /// Returns the header of the DiME item.
    /// </summary>
    public override string Header => ItemHeader;
    /// <summary>
    /// Returns the public key attached to the identity of an entity. The Key instance returned will only contain a
    /// public key with the capability 'Sign'.
    /// </summary>
    public Key? PublicKey
    {
        get
        {
            if (_publicKey is not null) return _publicKey;
            _publicKey = new Key(new List<KeyCapability>() {KeyCapability.Sign}, GetClaim<string>(Claim.Pub),
                Claim.Pub);
            return _publicKey;
        }
    }
    private Key? _publicKey;

    /// <summary>
    /// Returns a list of any capabilities given to an identity. These are requested by an entity and approved (and
    /// potentially modified) by the issuing entity when issuing a new identity. Capabilities are usually used to
    /// determine what an entity may do with its issued identity.
    /// </summary>
    public ReadOnlyCollection<IdentityCapability>? Capabilities 
    { 
        get {
            if (_capabilities is not null) return _capabilities;
            var caps = GetClaim<List<string>>(Claim.Cap);
            if (caps != null)
                _capabilities = caps.ConvertAll(str =>
                {
                    Enum.TryParse(str, true, out IdentityCapability cap);
                    return cap;
                }).AsReadOnly();
            return _capabilities;
        } 
    }
    private ReadOnlyCollection<IdentityCapability>? _capabilities;
    /// <summary>
    /// Returns all principles assigned to an identity. These are key-value fields that further provide information
    /// about the entity. Using principles are optional.
    /// </summary>
    public Dictionary<string, object>? Principles
    {
        get
        {
            if (_principles is not null) return _principles;
            _principles = GetClaim<Dictionary<string, object>>(Claim.Pri);
            return _principles;
        }
    }
    private Dictionary<string, object>? _principles;
    /// <summary>
    /// Returns the parent identity of a trust chain for an identity. This is the issuing identity.
    /// </summary>
    public Identity? TrustChain { get; internal set; }        
    /// <summary>
    /// Returns if the identity has been self-issued. Self-issuing happens when the same entity issues its own identity.
    /// </summary>
    public bool IsSelfSigned => GetClaim<Guid>(Claim.Sub).Equals(GetClaim<Guid>(Claim.Iss)) && HasCapability(IdentityCapability.Self);

    /// <summary>
    /// Empty constructor, not to be used. Required for Generics.
    /// </summary>
    public Identity() { }

    /// <summary>
    /// Verifies the integrity and over all validity and trust of the item. If a key is provided, then verification will
    /// use that key. If verifyKey is omitted, then the local key ring will be used to verify signatures of the item.
    /// </summary>
    /// <param name="verifyKey">Key used to verify the item, may be null.</param>
    /// <param name="linkedItems">A list of item where item links should be verified, may be null.</param>
    /// <returns>The integrity state of the verification.</returns>
    public override IntegrityState Verify(Key? verifyKey = null, List<Item>? linkedItems = null)
    {
        if (TrustChain is null || verifyKey is not null) return base.Verify(verifyKey, linkedItems);
        var state = TrustChain.Verify();
        return !Dime.IsIntegrityStateValid(state) ? state : base.Verify(TrustChain.PublicKey, linkedItems);
    }
        
    /// <summary>
    /// Will check if the identity has a specific capability.
    /// </summary>
    /// <param name="identityCapability">The capability to check for.</param>
    /// <returns>Boolean to indicate if the identity has the capability or not.</returns>
    public bool HasCapability(IdentityCapability identityCapability)
    {
        return Capabilities?.Contains(identityCapability) ?? false;
    }

    /// <summary>
    /// Will check if an identity is within a particular ambit.
    /// </summary>
    /// <param name="ambit">The ambit to check for.</param>
    /// <returns>true or false</returns>
    public bool HasAmbit(string ambit)
    {
        var list = GetClaim<List<string>>(Claim.Amb);
        if (list is not null && list.Count > 0)
            return list.Contains(ambit);
        return false;
    }

    #endregion

    #region -- INTERNAL --

    internal Identity(string? systemName, Guid subjectId, string? publicKey, DateTime issuedAt, DateTime expiresAt, Guid issuerId, List<string>? capabilities, Dictionary<string, object>? principles, List<string>? ambit, List<string>? methods) 
    {
        if (string.IsNullOrEmpty(systemName)) { throw new ArgumentNullException(nameof(systemName), "System name must not be null or empty."); }
        var claims = Claims();
        if (claims is not null)
        {
            claims.Put(Claim.Uid, Guid.NewGuid());
            claims.Put(Claim.Sys, systemName);
            claims.Put(Claim.Sub, subjectId);
            claims.Put(Claim.Iss, issuerId);
            claims.Put(Claim.Iat, issuedAt);
            claims.Put(Claim.Exp, expiresAt);
            claims.Put(Claim.Pub, publicKey);
            claims.Put(Claim.Cap, capabilities);
            claims.Put(Claim.Pri, principles);
            if (ambit is not null && ambit.Count > 0)
                claims.Put(Claim.Amb, ambit);
            if (methods is not null && methods.Count > 0)
                claims.Put(Claim.Mtd, methods);
        }
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
        if (components.Count <= MaximumNbrComponents)
        {
            if (components.Count == MaximumNbrComponents) // There is also a trust chain identity
            {
                var issuer = Utility.FromBase64(components[ComponentsChainIndex]);
                TrustChain = Identity.FromEncoded(Encoding.UTF8.GetString(issuer));
            }
            IsSigned = true; // Identities are always signed
        }
        else
            throw new FormatException(
                $"More components in item than expected, expected maximum {MaximumNbrComponents}, got {components.Count}.");
    }

    /// <inheritdoc />
    protected override void CustomEncoding(StringBuilder builder)
    {
        base.CustomEncoding(builder);
        if (TrustChain is null) return; // Not trusted chain stored, early return
        builder.Append(Dime.ComponentDelimiter);
        builder.Append(Utility.ToBase64(TrustChain.ForExport()));
    }

    /// <inheritdoc />
    protected override int GetMinNbrOfComponents()
    {
        return MinimumNbrComponents;
    }

    #endregion

    #region -- PRIVATE --

    private static readonly List<Claim> AllowedClaims = new() { Claim.Amb, Claim.Aud, Claim.Ctx, Claim.Exp, Claim.Iat, Claim.Iss, Claim.Kid, Claim.Mtd, Claim.Pri, Claim.Sub, Claim.Sys, Claim.Uid };
    private new const int MinimumNbrComponents = 3;
    private const int MaximumNbrComponents = MinimumNbrComponents + 1;
    private const int ComponentsChainIndex = 2;

    private new static Identity FromEncoded(string encoded)
    {
        var identity = new Identity();
        identity.Decode(encoded);
        return identity;
    }
        
    #endregion

}