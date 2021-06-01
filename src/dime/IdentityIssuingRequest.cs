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
            if (Dime.GetType(encoded) != typeof(IdentityIssuingRequest)) { throw new ArgumentException("Invalid header."); }
            string[] components = encoded.Split(new char[] { IdentityIssuingRequest._MAIN_DELIMITER });
            if (components.Length != 3 ) { throw new ArgumentException("Unexpected number of components found then decoding identity issuing request."); }
            ProfileVersion profile;
            Enum.TryParse<ProfileVersion>(components[0].Substring(1), true, out profile);
            this.Profile = profile;
            byte[] json = Utility.FromBase64(components[1]);
            this._claims = JsonSerializer.Deserialize<IirClaims>(json);
            this._capabilities = new List<string>(this._claims.cap).ConvertAll(str => { Capability cap; Enum.TryParse<Capability>(str, true, out cap); return cap; });
            this._signature = components[2];
            this._encoded = encoded.Substring(0, encoded.LastIndexOf(IdentityIssuingRequest._MAIN_DELIMITER));
        }

        protected override string Encode()
        {
            if (this._encoded == null) 
            { 
                StringBuilder builder = new StringBuilder(); 
                builder.Append('i'); // The header of an DiME identity issuing request
                builder.Append((int)this.Profile);
                builder.Append(Dime._MAIN_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

        #region -- PRIVATE --
        
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