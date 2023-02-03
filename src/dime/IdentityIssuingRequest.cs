//
//  IdentityIssuingRequest.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//

#nullable enable
using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using DiME.Capability;
using DiME.Exceptions;

namespace DiME;

/// <summary>
/// Class used to create a request for the issuing of an identity to an entity. This will contain a locally
/// generated public key (where the private key remains locally), capabilities requested and principles claimed. An
/// issuing entity uses the Identity Issuing Request (IIR) to validate and then issue a new identity for the entity.
/// </summary>
public class IdentityIssuingRequest: Item
{
    #region -- PUBLIC --

    /// <summary>
    ///  The item header for DiME Identity Issuing Request items.
    /// </summary>
    public const string ItemHeader = "IIR";
    /// <summary>
    /// Returns the header of the DiME item.
    /// </summary>
    public override string Header => ItemHeader;
    /// <summary>
    /// Returns the public key attached to the IIR. This is the public key attached by the entity and will get
    /// included in any issued identity. The equivalent secret (private) key was used to sign the IIR, thus the
    /// public key can be used to verify the signature. This must be a key of type IDENTITY.
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
    /// Returns a list of any capabilities requested by this IIR. Capabilities are usually used to
    /// determine what an entity may do with its issued identity.
    /// </summary>
    public ReadOnlyCollection<IdentityCapability>? Capabilities 
    { 
        get {
            if (_capabilities is not null) return _capabilities;
            var caps = Claims()?.Get<List<string>>(Claim.Cap);
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
    /// Returns all principles provided in the IIR. These are key-value fields that further provide information
    /// about the entity. Using principles are optional.
    /// </summary>
    public Dictionary<string, object>? Principles => _principles ??= Claims()?.Get<Dictionary<string, object>>(Claim.Pri);
    private Dictionary<string, object>? _principles;
        
    /// <summary>
    /// Empty constructor, not to be used. Required for Generics.
    /// </summary>
    public IdentityIssuingRequest() { }

    /// <summary>
    /// This will generate a new IIR from a Key instance together with a list of wished for capabilities and
    /// principles to include in any issued identity. The Key instance must be of type IDENTITY.
    /// </summary>
    /// <param name="key">The Key instance to use.</param>
    /// <param name="capabilities">A list of capabilities that should be requested.</param>
    /// <param name="principles">A map of key-value fields that should be included in an issued identity.</param>
    /// <returns>An IIR that can be used to issue a new identity (or sent to a trusted entity for issuing).</returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="ArgumentNullException"></exception>
    public static IdentityIssuingRequest Generate(Key key, List<IdentityCapability>? capabilities = null, Dictionary<string, object>? principles = null) 
    {
        if (!key.HasCapability(KeyCapability.Sign)) { throw new ArgumentException("Key missing required 'sign' capability.", nameof(key)); }
        if (key.Secret == null) { throw new ArgumentNullException(nameof(key), "Private key must not be null"); }
        var iir = new IdentityIssuingRequest();
        var claims = iir.Claims();
        claims?.Put(Claim.Uid, Guid.NewGuid());
        claims?.Put(Claim.Iat, Utility.CreateDateTime());
        claims?.Put(Claim.Pub, key.Public);
        var capabilitiesToSet = capabilities;
        if (capabilitiesToSet == null || capabilitiesToSet.Count == 0) 
            capabilitiesToSet = new List<IdentityCapability>() { IdentityCapability.Generic }; 
        else 
            capabilitiesToSet = capabilities;
        claims?.Put(Claim.Cap, capabilitiesToSet?.ConvertAll(obj => obj.ToString().ToLower()));
        if (principles is not null && principles.Count > 0)
            claims?.Put(Claim.Pri, principles);
        iir.IsLegacy = key.IsLegacy;
        iir.Sign(key);
        return iir;
    }

    /// <summary>
    /// Checks if the IIR includes a request for a particular capability.
    /// </summary>
    /// <param name="identityCapability">The capability to check for.</param>
    /// <returns>true or false.</returns>
    public bool WantsCapability(IdentityCapability identityCapability)
    {
        return Capabilities?.Any(cap => cap == identityCapability) ?? false;
    }
        
    /// <summary>
    /// Will issue a new Identity instance from the IIR. This method should only be called after the IIR has been
    /// validated to meet context and application specific requirements. The only exception is the capabilities,
    /// that may be validated during the issuing, by providing allowed and required capabilities. If system is
    /// omitted, then the issued identity will be set to the system same as the issuing identity.
    /// </summary>
    /// <param name="subjectId">The subject identifier of the entity. For a new identity this may be anything, for a
    /// re-issue it should be the same as subject identifier used previously.</param>
    /// <param name="validFor">The number of seconds that the identity should be valid for, from the time of issuing.</param>
    /// <param name="issuerKey">The Key of the issuing entity, must contain a secret key of type IDENTIFY.</param>
    /// <param name="issuerIdentity">The Identity instance of the issuing entity. If part of a trust chain, then
    /// this will be attached to the newly issued Identity.</param>
    /// <param name="includeChain">If set to true then the trust chain will be added to the newly issued identity.
    /// The chain will only the included if the issuing identity is not the root node.</param>
    /// <param name="allowedCapabilities">A list of capabilities that may be present in the IIR to allow issuing.</param>
    /// <param name="requiredCapabilities">A list of capabilities that will be added (if not present in the IIR)
    /// before issuing.</param>
    /// <param name="systemName">The name of the system, or network, that the identity should be a part of.</param>
    /// <param name="ambit">A list of ambit that will apply to the issued identity.</param>
    /// <param name="methods">A list of methods that will apply to the issued identity.</param>
    /// <returns>An Identity instance that may be sent back to the entity that proved the IIR.</returns>
    /// <exception cref="ArgumentNullException"></exception>
    public Identity Issue(Guid subjectId, long validFor, Key issuerKey, Identity? issuerIdentity, bool includeChain, List<IdentityCapability> allowedCapabilities, List<IdentityCapability>? requiredCapabilities = null, string? systemName = null, List<string>? ambit = null, List<string>? methods = null) 
    {    
        if (issuerIdentity == null) { throw new ArgumentNullException(nameof(issuerIdentity), "Issuer identity must not be null."); }
        var sys = !string.IsNullOrEmpty(systemName) ? systemName : issuerIdentity.GetClaim<string>(Claim.Sys);
        return IssueNewIdentity(sys, subjectId, validFor, issuerKey, issuerIdentity, includeChain, allowedCapabilities, requiredCapabilities, ambit, methods);
    }

    /// <summary>
    /// Will issue a new Identity instance from the IIR. The issued identity will be self-issued as it will be
    /// signed by the same key that also created the IIR. This is normally used when creating a root identity for a trust chain.
    /// </summary>
    /// <param name="subjectId">The subject identifier of the entity. For a new identity this may be anything, for
    /// a re-issue it should be the same as subject identifier used previously.</param>
    /// <param name="validFor">The number of seconds that the identity should be valid for, from the time of issuing.</param>
    /// <param name="issuerKey">The Key of the issuing entity, must contain a secret key of type IDENTIFY.</param>
    /// <param name="systemName">The name of the system, or network, that the identity should be a part of.</param>
    /// <param name="ambit">A list of ambit that will apply to the issued identity.</param>
    /// <param name="methods">A list of methods that will apply to the issued identity.</param>
    /// <returns></returns>
    /// <exception cref="ArgumentNullException"></exception>
    public Identity SelfIssue(Guid subjectId, long validFor, Key issuerKey, string systemName, List<string>? ambit = null, List<string>? methods = null)
    {
        if (string.IsNullOrEmpty(systemName)) { throw new ArgumentNullException(nameof(systemName), "System name must not be null or empty."); }
        return IssueNewIdentity(systemName, subjectId, validFor, issuerKey, null, false, null, null, ambit, methods);
    }
        
    #endregion
        
    # region -- INTERNAL --

    internal new static IdentityIssuingRequest FromEncoded(string encoded)
    {
        var iir = new IdentityIssuingRequest();
        iir.Decode(encoded);
        return iir;
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
        IsSigned = true; // Identity issuing requests are always signed
    }

    /// <inheritdoc />
    protected override int GetMinNbrOfComponents()
    {
        return MinimumNbrComponents;
    }

    #endregion

    #region -- PRIVATE --
    
    private static readonly List<Claim> AllowedClaims = new() { Claim.Amb, Claim.Aud, Claim.Ctx, Claim.Exp, Claim.Iat, Claim.Iss, Claim.Isu, Claim.Kid, Claim.Mtd, Claim.Pri, Claim.Sub, Claim.Sys, Claim.Uid };
    private new const int MinimumNbrComponents = 3;
        
    private Identity IssueNewIdentity(string? systemName, Guid subjectId, long validFor, Key issuerKey, Identity? issuerIdentity, bool includeChain, List<IdentityCapability>? allowedCapabilities, IReadOnlyCollection<IdentityCapability>? requiredCapabilities = null, List<string>? ambit = null, List<string>? methods = null)
    {
        var isSelfSign = PublicKey.Public.Equals(issuerKey.Public);
        if (isSelfSign && issuerIdentity != null)
            throw new ArgumentException(
                "Unable to issue new identity since both issuing public key and issued public key is the same.");
        CompleteCapabilities(allowedCapabilities, requiredCapabilities, isSelfSign);
        if (!isSelfSign && issuerIdentity != null && !issuerIdentity.HasCapability(IdentityCapability.Issue))
            throw new CapabilityException("Issuing identity missing 'issue' capability.");
        var now = Utility.CreateDateTime();
        var expires = now.AddSeconds(validFor);
        var issuerId = issuerIdentity?.GetClaim<Guid>(Claim.Sub) ?? subjectId;
        var identity = new Identity(systemName, 
            subjectId, 
            PublicKey?.Public, 
            now, 
            expires, 
            issuerId, 
            Claims()?.Get<List<string>>(Claim.Cap), 
            Claims()?.Get<Dictionary<string, object>>(Claim.Pri), 
            ambit, 
            methods);
        if (issuerIdentity is not null)
        {
            var state = issuerIdentity.VerifyDates();
            if (!Dime.IsIntegrityStateValid(state))
                throw new InvalidOperationException("Unable to issue new identity, issuer identity has invalid dates.");
            if (includeChain && !Dime.KeyRing.Contains(issuerIdentity))
                // The chain will only be set if the issuer identity is not a trusted identity in the key ring
                identity.TrustChain = issuerIdentity;
        }
        identity.IsLegacy = IsLegacy;
        identity.Sign(issuerKey);
        return identity;
    }

    private void CompleteCapabilities(List<IdentityCapability>? allowedCapabilities, IReadOnlyCollection<IdentityCapability>? requiredCapabilities, bool isSelfSign)
    {
        var caps = Capabilities is not null ? new List<IdentityCapability>(Capabilities) : new List<IdentityCapability> {IdentityCapability.Generic};
        if (caps.Count == 0) { caps.Add(IdentityCapability.Generic); }
        if (isSelfSign)
        {
            if (!WantsCapability(IdentityCapability.Self))
                caps.Add(IdentityCapability.Self);
        }
        else
        {
            if (WantsCapability(IdentityCapability.Self))
                throw new ArgumentException(
                    "Unable to issue identity, only self-issued identities may request Self capability.");
            if (allowedCapabilities is null || allowedCapabilities.Count == 0) { throw new ArgumentException("Unable to issue identity, allowed capabilities must be defined to issue identity.", nameof(allowedCapabilities)); }
            if (caps.Except(allowedCapabilities).Any()) { throw new CapabilityException("Unable to issue identity, IIR contains one or more disallowed capabilities."); }
            if (requiredCapabilities is not null && requiredCapabilities.Except(caps).Any()) { throw new CapabilityException("Unable to issue identity, IIR is missing one or more required capabilities."); }
        }
        Claims()?.Put(Claim.Cap, caps.ConvertAll(obj => obj.ToString().ToLower()));
        _capabilities = null;
    }

    #endregion

}