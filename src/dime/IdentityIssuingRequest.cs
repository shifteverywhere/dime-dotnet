//
//  IdentityIssuingRequest.cs
//  DiME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;
using System.Collections.Generic;

namespace ShiftEverywhere.DiME
{
    public class IdentityIssuingRequest: Dime
    {
        #region -- PUBLIC --

        public const string Identifier = "aW8uZGltZWZvcm1hdC5paXI"; // base64 of io.dimeformat.iir
        public const long VALID_FOR_1_YEAR = 365 * 24 * 60 * 60;
        /// <summary></summary>
        public long IssuedAt { get { return this._claims.iat;} }
        /// <summary></summary>
        public string IdentityKey { get { return this._claims.iky; } }

        public IdentityIssuingRequest() { }

        public static IdentityIssuingRequest Generate(KeyBox keypair, List<Capability> capabilities = null) 
        {
            if (!Crypto.SupportedProfile(keypair.Profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            if (keypair.Type != KeyType.Identity) { throw new ArgumentNullException(nameof(keypair), "KeyPair of invalid type."); }
            if (keypair.Key == null) { throw new ArgumentNullException(nameof(keypair), "Private key must not be null"); }
            IdentityIssuingRequest iir = new IdentityIssuingRequest();
            iir.Profile = keypair.Profile;
            if (capabilities == null || capabilities.Count == 0) { iir._capabilities = new List<Capability>() 
            { 
                Capability.Generic }; 
            }
            else 
            { 
                iir._capabilities = capabilities; 
            }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string[] cap;
            if (capabilities != null && capabilities.Count > 0)
            {
                cap = capabilities.ConvertAll(c => c.ToString().ToLower()).ToArray();
            }
            else
            {
                cap = new string[1] { Capability.Generic.ToString().ToLower() };
            }
            iir._claims = new IirClaims(now, keypair.PublicKey, cap);
            iir.Seal(keypair.Key);
            return iir;
        }

        public override void Verify()
        {
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() < this.IssuedAt) { throw new DateExpirationException("An identity issuing request cannot be issued in the future."); }
            base.Verify(this.IdentityKey);
        }

        public bool WantsCapability(Capability capability)
        {
            return this._capabilities.Any(cap => cap == capability);
        }

        /// <summary>Issues a new signed identity from an identity issuing request (IIR). The new identity
        /// will be signed by the provided issuerIdentity. The identity of the issuer must either be trusted
        /// by the TrustedIdentity, or be the TrustedIdentity. If the issuerIdentity is omitted, then the 
        /// returned identity will be self-signed. </summary>
        /// <param name="irr">The IIR from the subject.</param>
        /// <param name="subjectId">The subject id that should be associated with the identity.</param>
        /// <param name="issuerKeypair">The key pair of the issuer.</param>
        /// <param name="allowedCapabilities">The capabilities allowed for the to be issued identity.</param>
        /// <param name="issuerIdentitys">The identity of the issuer (optional).</param>
        /// <returns>Returns an imutable Identity instance.</returns>
        public Identity IssueIdentity(Guid subjectId, long validFor, List<Capability> allowedCapabilities, KeyBox issuerKeypair, Identity issuerIdentity) 
        {    
            bool isSelfSign = (issuerIdentity == null || this.IdentityKey == issuerKeypair.PublicKey);
            this.CompleteCapabilities(allowedCapabilities, isSelfSign);
            if (isSelfSign || issuerIdentity.HasCapability(Capability.Issue))
            {
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                Guid issuerId = issuerIdentity != null ? issuerIdentity.SubjectId : subjectId;
                Identity identity = new Identity(subjectId, this.IdentityKey, now, (now + validFor), issuerId, this._capabilities, this.Profile);
                if (Identity.TrustedIdentity != null && issuerIdentity != null && issuerIdentity.SubjectId != Identity.TrustedIdentity.SubjectId)
                {
                    issuerIdentity.Verify();
                    // The chain will only be set if this is not the trusted identity (and as long as one is set)
                    identity.TrustChain = issuerIdentity;
                }
                identity.Seal(issuerKeypair.Key);
                return identity;
            }
            throw new IdentityCapabilityException("Issuing identity missing 'issue' capability.");
        }

        #endregion

        #region -- PROTECTED --

        protected override void Populate(string encoded) 
        {
            string[] components = encoded.Split(new char[] { Dime._COMPONENT_DELIMITER });
            if (components.Length != IdentityIssuingRequest._NBR_EXPECTED_COMPONENTS ) { throw new DataFormatException($"Unexpected number of components for identity issuing request, expected {IdentityIssuingRequest._NBR_EXPECTED_COMPONENTS}, got {components.Length}."); }
            if (components[IdentityIssuingRequest._IDENTIFIER_INDEX] != IdentityIssuingRequest.Identifier) { throw new DataFormatException($"Unexpected object identifier, expected: \"{IdentityIssuingRequest.Identifier}\", got \"{components[IdentityIssuingRequest._IDENTIFIER_INDEX]}\"."); }
            byte[] json = Utility.FromBase64(components[IdentityIssuingRequest._CLAIMS_INDEX]);
            this._claims = JsonSerializer.Deserialize<IirClaims>(json);
            this._capabilities = new List<string>(this._claims.cap).ConvertAll(str => { Capability cap; Enum.TryParse<Capability>(str, true, out cap); return cap; });
        }

        protected override void Encode(StringBuilder builder)
        {
            builder.Append(IdentityIssuingRequest.Identifier);
            builder.Append(Dime._COMPONENT_DELIMITER);
            builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
        }

        #endregion

        #region -- PRIVATE --
        
        private const int _NBR_EXPECTED_COMPONENTS = 2;
        private const int _IDENTIFIER_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;

        private struct IirClaims
        {
            public long iat { get; set; }
            public string iky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }

            [JsonConstructor]
            public IirClaims(long iat, string iky, string[] cap = null)
            {
                this.iat = iat;
                this.iky = iky;
                this.cap = cap;
            }
        }
        
        private IirClaims _claims;
        private List<Capability> _capabilities { get; set; }

        private void CompleteCapabilities(List<Capability> allowedCapabilities, bool isSelfSign)
        {
            if (this._capabilities == null) { this._capabilities = new List<Capability> { Capability.Generic }; }
            if (this._capabilities.Count == 0) { this._capabilities.Add(Capability.Generic); }
            if (isSelfSign)
            {
                if (!this.WantsCapability(Capability.Self))
                {
                    this._capabilities.Add(Capability.Self);
                }
            }
            else 
            {
                if (allowedCapabilities == null || allowedCapabilities.Count == 0) { throw new IdentityCapabilityException("Allowed capabilities must be defined to issue identity."); }
                foreach(Capability cap in this._capabilities)
                {
                    if (!allowedCapabilities.Any<Capability>(c => c == cap))
                    {
                        throw new IdentityCapabilityException($"Illegal capabilities requested: {this._capabilities}");
                    }
                }
            }
        }


        #endregion

    }

}