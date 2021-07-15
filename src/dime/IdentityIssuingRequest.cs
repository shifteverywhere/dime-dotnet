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
    public class IdentityIssuingRequest: Item
    {
        #region -- PUBLIC --
        public const string IID = "aWly"; // base64 of 'iir'
        public override string ItemIdentifier { get { return IdentityIssuingRequest.IID; } }
        /// <summary></summary>
        public override Guid UID { get { return this._claims.uid; } }
        /// <summary></summary>
        public long IssuedAt { get { return this._claims.iat; } }
        /// <summary></summary>
        public string PublicKey { get { return this._claims.pub; } }

        public IdentityIssuingRequest() { }

        public static IdentityIssuingRequest Generate(KeyBox keybox, List<Capability> capabilities = null) 
        {
            if (!Crypto.SupportedProfile(keybox.Profile)) { throw new ArgumentException("Unsupported profile version.", nameof(keybox)); }
            if (keybox.Type != KeyType.Identity) { throw new ArgumentException("KeyBox of invalid type.", nameof(keybox)); }
            if (keybox.Key == null) { throw new ArgumentNullException(nameof(keybox), "Private key must not be null"); }
            IdentityIssuingRequest iir = new IdentityIssuingRequest();
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
            iir._claims = new IirClaims(Guid.NewGuid(), now, keybox.PublicKey, cap);
            iir._signature = Crypto.GenerateSignature(iir.Encode(), keybox);
            return iir;
        }

        public void Verify()
        {
            Verify(KeyBox.FromBase58Key(this.PublicKey));
        }

        public override void Verify(KeyBox keybox)
        {
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() < this.IssuedAt) { throw new DateExpirationException("An identity issuing request cannot be issued at in the future."); }
            base.Verify(keybox);
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
            bool isSelfSign = (issuerIdentity == null || this.PublicKey == issuerKeypair.PublicKey);
            this.CompleteCapabilities(allowedCapabilities, isSelfSign);
            if (isSelfSign || issuerIdentity.HasCapability(Capability.Issue))
            {
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                Guid issuerId = issuerIdentity != null ? issuerIdentity.SubjectId : subjectId;
                Identity identity = new Identity(subjectId, this.PublicKey, now, (now + validFor), issuerId, this._capabilities, Profile.Uno);
                if (Identity.TrustedIdentity != null && issuerIdentity != null && issuerIdentity.SubjectId != Identity.TrustedIdentity.SubjectId)
                {
                    issuerIdentity.VerifyTrust();
                    // The chain will only be set if this is not the trusted identity (and as long as one is set)
                    identity.TrustChain = issuerIdentity;
                }
                identity.Seal(issuerKeypair.Key);
                return identity;
            }
            throw new IdentityCapabilityException("Issuing identity missing 'issue' capability.");
        }

        internal new static IdentityIssuingRequest FromEncoded(string encoded)
        {
            IdentityIssuingRequest iir = new IdentityIssuingRequest();
            iir.Decode(encoded);
            return iir;
        }

        #endregion

        # region -- PROTECTED --

        protected override void Decode(string encoded) 
        {
            string[] components = encoded.Split(new char[] { Envelope._COMPONENT_DELIMITER });
            if (components.Length != IdentityIssuingRequest._NBR_COMPONENTS_WITHOUT_SIGNATURE && components.Length != IdentityIssuingRequest._NBR_COMPONENTS_WITH_SIGNATURE) { throw new DataFormatException($"Unexpected number of components for identity issuing request, expected {IdentityIssuingRequest._NBR_COMPONENTS_WITHOUT_SIGNATURE} or  {IdentityIssuingRequest._NBR_COMPONENTS_WITH_SIGNATURE}, got {components.Length}."); }
            if (components[IdentityIssuingRequest._IDENTIFIER_INDEX] != IdentityIssuingRequest.IID) { throw new DataFormatException($"Unexpected object identifier, expected: \"{IdentityIssuingRequest.IID}\", got \"{components[IdentityIssuingRequest._IDENTIFIER_INDEX]}\"."); }
            byte[] json = Utility.FromBase64(components[IdentityIssuingRequest._CLAIMS_INDEX]);
            this._claims = JsonSerializer.Deserialize<IirClaims>(json);
            this._capabilities = new List<string>(this._claims.cap).ConvertAll(str => { Capability cap; Enum.TryParse<Capability>(str, true, out cap); return cap; });
            if (components.Length == _NBR_COMPONENTS_WITH_SIGNATURE)
            {
                this._encoded = encoded.Substring(0, encoded.LastIndexOf(Envelope._COMPONENT_DELIMITER));
                this._signature = components[IdentityIssuingRequest._SIGNATURE_INDEX];
            }
        }

        protected override string Encode()
        {
            if (this._encoded == null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(IdentityIssuingRequest.IID);
                builder.Append(Envelope._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

        #region -- PRIVATE --
        
        private const int _NBR_COMPONENTS_WITHOUT_SIGNATURE = 2;
        private const int _NBR_COMPONENTS_WITH_SIGNATURE = 3;
        private const int _IDENTIFIER_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;
        private const int _SIGNATURE_INDEX = 2;

        private IirClaims _claims;
        private List<Capability> _capabilities { get; set; }

        private struct IirClaims
        {
            public Guid uid { get; set; }
            public long iat { get; set; }
            public string pub { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }

            [JsonConstructor]
            public IirClaims(Guid uid, long iat, string pub, string[] cap = null)
            {
                this.uid = uid;
                this.iat = iat;
                this.pub = pub;
                this.cap = cap;
            }
        }

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