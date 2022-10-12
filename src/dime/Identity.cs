//
//  Identity.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace DiME;

///<summary>
/// Represents a digital identity of an entity. Can be self-signed or signed by a trusted identity (and thus be part
/// of a trust chain.
///</summary>
public class Identity: Item
{
    #region -- PUBLIC --

    /// <summary>
    /// A shared trusted identity that acts as the root identity in the trust chain.
    /// </summary>
    [Obsolete("Obsolete method, use Dime.TrustedIdentity instead.")]        
    public static Identity TrustedIdentity => Dime.TrustedIdentity;
    /// <summary>
    /// A tag identifying the Di:ME item type, part of the header.
    /// </summary>
    public const string ItemIdentifier = "ID";
    /// <summary>
    /// Returns the tag of the Di:ME item.
    /// </summary>
    public override string Identifier => ItemIdentifier;
    /// <summary>
    /// Returns the name of the system or network that the entity belongs to. If issued by another entity and part
    /// of a trust chain, then all entities will share the same system name.
    /// </summary>
    public string SystemName => Claims().Get<string>(Claim.Sys);

    /// <summary>
    /// Returns the entity's subject identifier. This is, within the system, defined by system name, unique for one
    /// specific entity.
    /// </summary>
    public Guid SubjectId
    {
        get
        {
            var guid = Claims().GetGuid(Claim.Sub);
            if (guid is null) return Guid.Empty;
            return (Guid) guid;
        }
    } 
    /// <summary>
    /// Returns the public key attached to the identity of an entity. The Key instance returned will only contain a
    /// public key or type IDENTITY.
    /// </summary>
    public Key PublicKey => Claims().GetKey(Claim.Pub, new List<KeyCapability>() { KeyCapability.Sign });
    /// <summary>
    /// Returns a list of any capabilities given to an identity. These are requested by an entity and approved (and
    /// potentially modified) by the issuing entity when issuing a new identity. Capabilities are usually used to
    /// determine what an entity may do with its issued identity.
    /// </summary>
    public ReadOnlyCollection<IdentityCapability> Capabilities 
    { 
        get {
            if (_capabilities is not null) return _capabilities;
            var caps = Claims().Get<List<string>>(Claim.Cap);
            if (caps != null)
                _capabilities = caps.ConvertAll(str =>
                {
                    Enum.TryParse(str, true, out IdentityCapability cap);
                    return cap;
                }).AsReadOnly();
            return _capabilities;
        } 
    }
    private ReadOnlyCollection<IdentityCapability> _capabilities;
    /// <summary>
    /// Returns all principles assigned to an identity. These are key-value fields that further provide information
    /// about the entity. Using principles are optional.
    /// </summary>
    public Dictionary<string, object> Principles
    {
        get
        {
            if (_principles is not null) return _principles;
            _principles = Claims().Get<Dictionary<string, object>>(Claim.Pri);
            return _principles;
        }
    }
    private Dictionary<string, object> _principles;
    /// <summary>
    /// Returns an ambit list assigned to an identity. An ambit defines the scope, region or role where an identity
    /// may be used.
    /// </summary>
    [Obsolete("Obsolete method, use AmbitList instead.")]
    public IList<string> Ambits => AmbitList;
    /// <summary>
    /// Returns an ambit list assigned to an identity. An ambit defines the scope, region or role where an identity
    /// may be used.
    /// </summary>
    public IList<string> AmbitList => Claims().Get<IList<string>>(Claim.Amb);
    /// <summary>
    /// Returns a list of methods associated with an identity. The usage of this is normally context or application
    /// specific, and may specify different methods that can be used convert, transfer or further process a Di:ME
    /// identity.
    /// </summary>
    public IList<string> Methods => Claims().Get<IList<string>>(Claim.Mtd);
    /// <summary>
    /// Returns if the identity has been self-issued. Self-issuing happens when the same entity issues its own identity.
    /// </summary>
    public bool IsSelfSigned => SubjectId == IssuerId && HasCapability(IdentityCapability.Self);
    /// <summary>
    /// Returns the parent identity of a trust chain for an identity. This is the issuing identity.
    /// </summary>
    public Identity TrustChain { get; internal set; }        /// <summary>
    /// Sets an Identity instance to be the trusted identity used for verifying a trust chain of other Identity
    /// instances. This is normally the root identity of a trust chain.
    /// </summary>
    /// <param name="trustedIdentity">The identity to set as the trusted identity.</param>
    [Obsolete("Obsolete method, use Dime.TrustedIdentity instead.")] 
    public static void SetTrustedIdentity(Identity trustedIdentity) { Dime.TrustedIdentity = trustedIdentity; }
        
    /// <summary>
    /// Empty constructor, not to be used. Required for Generics.
    /// </summary>
    public Identity() { }

    /// <summary>
    /// Verifies if an Identity instance is valid and can be trusted. Will validate issued at and expires at dates, look at a trust chain (if present) and verify the signature with the attached public key.
    /// </summary>
    /// <exception cref="InvalidOperationException"></exception>
    /// <exception cref="DateExpirationException">If the issued at date is in the future, or if the expires at date is in the past.</exception>
    /// <exception cref="UntrustedIdentityException">If the trust of the identity could not be verified.</exception>
    [Obsolete("This method is deprecated since 1.0.1 and will be removed in a future version use IsTrusted() or IsTrusted(Identity) instead.")]
    public void VerifyTrust()
    {
        if (!IsTrusted()) 
        {
            throw new UntrustedIdentityException("Identity cannot be trusted.");
        }
    }

    /// <summary>
    /// Will verify if an identity can be trusted using the globally set Trusted Identity
    /// (SetTrustedIdentity(Identity)). Once trust has been established it will also verify the issued at date and
    /// the expires at date to see if these are valid.
    /// </summary>
    /// <returns>True if the identity is trusted.</returns>
    /// <exception cref="InvalidOperationException">If global trusted identity is not set.</exception>
    public bool IsTrusted()
    {
        if (Dime.TrustedIdentity == null) { throw new InvalidOperationException("Unable to verify trust, no global trusted identity set."); }
        return IsTrusted(Dime.TrustedIdentity);
    }

    /// <summary>
    /// Will verify if an identity can be trusted by a provided identity. An identity is trusted if it exists on the
    /// same branch and later in the branch as the provided identity. Once trust has been established it will also
    /// verify the issued at date and the expires at date to see if these are valid.
    /// </summary>
    /// <param name="trustedIdentity">The identity to verify the trust from.</param>
    /// <returns>True if the identity is trusted.</returns>
    /// <exception cref="DateExpirationException">If the issued at date is in the future, or if the expires at date is in the past.</exception>
    public bool IsTrusted(Identity trustedIdentity)
    {
        if (trustedIdentity == null) { throw new ArgumentNullException(nameof(trustedIdentity),"Unable to verify trust, provided trusted identity must not be null."); }
        if (VerifyChain(trustedIdentity) == null) return false;
        var now = Utility.CreateDateTime();
        if (IssuedAt > now) { throw new DateExpirationException("Identity is not yet valid, issued at date in the future."); }
        if (IssuedAt > ExpiresAt) { throw new DateExpirationException("Invalid expiration date, expires at before issued at."); }
        if (ExpiresAt < now) { throw new DateExpirationException("Identity has expired."); }
        return true;
    }
        
    /// <summary>
    /// Will check if the identity has a specific capability.
    /// </summary>
    /// <param name="identityCapability">The capability to check for.</param>
    /// <returns>Boolean to indicate if the identity has the capability or not.</returns>
    public bool HasCapability(IdentityCapability identityCapability)
    {
        return Capabilities.Contains(identityCapability);
    }

    /// <summary>
    /// Will check if an identity is within a particular ambit.
    /// </summary>
    /// <param name="ambit">The ambit to check for.</param>
    /// <returns>true or false</returns>
    public bool HasAmbit(string ambit)
    {
        if (AmbitList is not null && AmbitList.Count > 0)
            return AmbitList.Contains(ambit);
        return false;
    }

    #endregion

    #region -- INTERNAL --

    internal Identity(string systemName, Guid subjectId, string publicKey, DateTime issuedAt, DateTime expiresAt, Guid issuerId, List<string> capabilities, Dictionary<string, object> principles, List<string> ambit, List<string> methods) 
    {
        if (string.IsNullOrEmpty(systemName)) { throw new ArgumentNullException(nameof(systemName), "System name must not be null or empty."); }
        var claims = Claims();
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

    protected override void CustomEncoding(StringBuilder builder)
    {
        base.CustomEncoding(builder);
        if (TrustChain is null) return; // Not trusted chain stored, early return
        builder.Append(Dime.ComponentDelimiter);
        builder.Append(Utility.ToBase64(TrustChain.ForExport()));
    }

    protected override int GetMinNbrOfComponents()
    {
        return MinimumNbrComponents;
    }

    #endregion

    # region -- PROTECTED --

    #endregion

    #region -- PRIVATE --

    private new const int MinimumNbrComponents = 3;
    private const int MaximumNbrComponents = MinimumNbrComponents + 1;
    private const int ComponentsChainIndex = 2;

    private new static Identity FromEncoded(string encoded)
    {
        var identity = new Identity();
        identity.Decode(encoded);
        return identity;
    }

    private Identity VerifyChain(Identity trustedIdentity)
    {
        Identity verifyingIdentity;
        if (TrustChain != null && TrustChain.SubjectId.CompareTo(trustedIdentity.SubjectId) != 0)
        {
            verifyingIdentity = TrustChain.VerifyChain(trustedIdentity);
        }
        else
        {
            verifyingIdentity = trustedIdentity;
        }
        if (verifyingIdentity == null) return null;
        try
        {
            Verify(verifyingIdentity.PublicKey);
            return this;
        }
        catch (IntegrityException)
        {
            return null;
        }
    }
        
    #endregion

}