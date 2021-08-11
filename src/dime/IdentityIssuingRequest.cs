//
//  IdentityIssuingRequest.cs
//  Di:ME - Digital Identity Message Envelope
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

        public const long VALID_FOR_1_YEAR = 365 * 24 * 60 * 60; 
        public const string TAG = "IIR";
        public override string Tag { get { return IdentityIssuingRequest.TAG; } }
        /// <summary></summary>
        public override Guid UniqueId { get { return this._claims.uid; } }
        /// <summary></summary>
        public DateTime IssuedAt { get { return Utility.FromTimestamp(this._claims.iat); } }
        /// <summary></summary>
        public string PublicKey { get { return this._claims.pub; } }
        public Dictionary<string, dynamic> Principles { get { return this._claims.pri; } }

        public IdentityIssuingRequest() { }

        public static IdentityIssuingRequest Generate(Key key, List<Capability> capabilities = null, Dictionary<string, dynamic> principles = null) 
        {
            if (!Crypto.SupportedProfile(key.Profile)) { throw new ArgumentException("Unsupported profile version.", nameof(key)); }
            if (key.Type != KeyType.Identity) { throw new ArgumentException("Key of invalid type.", nameof(key)); }
            if (key.Secret == null) { throw new ArgumentNullException(nameof(key), "Private key must not be null"); }
            IdentityIssuingRequest iir = new IdentityIssuingRequest();
            if (capabilities == null || capabilities.Count == 0) 
                iir._capabilities = new List<Capability>() { Capability.Generic }; 
            else 
                iir._capabilities = capabilities; 
            DateTime now = DateTime.Now;
            string[] cap;
            if (capabilities != null && capabilities.Count > 0)
                cap = capabilities.ConvertAll(c => c.ToString().ToLower()).ToArray();
            else
                cap = new string[1] { Capability.Generic.ToString().ToLower() };
            iir._claims = new IirClaims(Guid.NewGuid(), Utility.ToTimestamp(now), key.Public, cap, principles);
            iir._signature = Crypto.GenerateSignature(iir.Encode(), key);
            return iir;
        }

        public void Verify()
        {
            Verify(Key.FromBase58Key(this.PublicKey));
        }

        public override void Verify(Key keybox)
        {
            if (DateTime.Now < this.IssuedAt) { throw new DateExpirationException("An identity issuing request cannot have an issued at date in the future."); }
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
        /// <param name="systemName">An unique name of the system where the identity is deployed (system, infrastructure, application, etc.).</param>
        /// <param name="subjectId">The subject id that should be associated with the identity.</param>
        /// <param name="issuerKey">The key pair of the issuer.</param>
        /// <param name="allowedCapabilities">The capabilities allowed for the to be issued identity.</param>
        /// <param name="issuerIdentitys">The identity of the issuer (optional).</param>
        /// <param name="ambit">The areas or regions where the identity is valid.</param>
        /// <returns>Returns an imutable Identity instance.</returns>
        public Identity Issue(Guid subjectId, double validFor, List<Capability> allowedCapabilities, Key issuerKey, Identity issuerIdentity, string[] ambit = null) 
        {    
            if (issuerIdentity == null) { throw new ArgumentNullException(nameof(issuerIdentity), "Issuer identity must not be null."); }
            return this.IssueIdentity(issuerIdentity.SystemName, subjectId, validFor, allowedCapabilities, issuerKey, issuerIdentity, ambit);
        }

        public Identity SelfIssue(Guid subjectId, double validFor, Key issuerKey, string systemName, string[] ambit = null)
        {
            if (systemName == null || systemName.Length == 0) { throw new ArgumentNullException(nameof(systemName), "System name must not be null or empty."); }
            return this.IssueIdentity(systemName, subjectId, validFor, null, issuerKey, null, ambit);
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
            if (components.Length != IdentityIssuingRequest._NBR_COMPONENTS_WITHOUT_SIGNATURE && components.Length != IdentityIssuingRequest._NBR_COMPONENTS_WITH_SIGNATURE) { throw new FormatException($"Unexpected number of components for identity issuing request, expected {IdentityIssuingRequest._NBR_COMPONENTS_WITHOUT_SIGNATURE} or  {IdentityIssuingRequest._NBR_COMPONENTS_WITH_SIGNATURE}, got {components.Length}."); }
            if (components[IdentityIssuingRequest._TAG_INDEX] != IdentityIssuingRequest.TAG) { throw new FormatException($"Unexpected item tag, expected: \"{IdentityIssuingRequest.TAG}\", got \"{components[IdentityIssuingRequest._TAG_INDEX]}\"."); }
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
                builder.Append(IdentityIssuingRequest.TAG);
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
        private const int _TAG_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;
        private const int _SIGNATURE_INDEX = 2;

        private IirClaims _claims;
        private List<Capability> _capabilities { get; set; }

        private struct IirClaims
        {
            public Guid uid { get; set; }
            public string iat { get; set; }
            public string pub { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public Dictionary<string, dynamic> pri {get; set; }

            [JsonConstructor]
            public IirClaims(Guid uid, string iat, string pub, string[] cap, Dictionary<string, dynamic>pri)
            {
                this.uid = uid;
                this.iat = iat;
                this.pub = pub;
                this.cap = cap;
                this.pri = pri;
            }
        }
        
        private Identity IssueIdentity(string systemName, Guid subjectId, double validFor, List<Capability> allowedCapabilities, Key issuerKey, Identity issuerIdentity, string[] ambit = null)
        {
            bool isSelfSign = (issuerIdentity == null || this.PublicKey == issuerKey.Public);
            this.CompleteCapabilities(allowedCapabilities, isSelfSign);
            if (isSelfSign || issuerIdentity.HasCapability(Capability.Issue))
            {
                DateTime now = DateTime.Now;
                DateTime expires = now.AddSeconds(validFor);
                Guid issuerId = issuerIdentity != null ? issuerIdentity.SubjectId : subjectId;
                Identity identity = new Identity(systemName, subjectId, this.PublicKey, now, expires, issuerId, this._capabilities, this.Principles, ambit);
                if (Identity.TrustedIdentity != null && issuerIdentity != null && issuerIdentity.SubjectId != Identity.TrustedIdentity.SubjectId)
                {
                    issuerIdentity.VerifyTrust();
                    // The chain will only be set if this is not the trusted identity (and as long as one is set)
                    identity.TrustChain = issuerIdentity;
                }
                identity.Sign(issuerKey);
                return identity;
            }
            throw new IdentityCapabilityException("Issuing identity missing 'issue' capability.");

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