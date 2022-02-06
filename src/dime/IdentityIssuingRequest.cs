//
//  IdentityIssuingRequest.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
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

        public const long _VALID_FOR_1_YEAR = 365L * 24 * 60 * 60; 
        public const string _TAG = "IIR";
        public override string Tag => _TAG;
        /// <summary></summary>
        public override Guid UniqueId => _claims.uid;
        /// <summary></summary>
        public DateTime IssuedAt => Utility.FromTimestamp(_claims.iat);
        /// <summary></summary>
        public string PublicKey => _claims.pub;
        public Dictionary<string, object> Principles => _claims.pri;
        
        public IdentityIssuingRequest() { }

        public static IdentityIssuingRequest Generate(Key key, List<Capability> capabilities = null, Dictionary<string, object> principles = null) 
        {
            if (key.Type != KeyType.Identity) { throw new ArgumentException("Key of invalid type.", nameof(key)); }
            if (key.Secret == null) { throw new ArgumentNullException(nameof(key), "Private key must not be null"); }
            var iir = new IdentityIssuingRequest();
            if (capabilities == null || capabilities.Count == 0) 
                iir._capabilities = new List<Capability>() { Capability.Generic }; 
            else 
                iir._capabilities = capabilities; 
            var now = DateTime.UtcNow;
            var cap = capabilities is {Count: > 0} ? capabilities.ConvertAll(c => c.ToString().ToLower()).ToArray() : new[] { Capability.Generic.ToString().ToLower() };
            iir._claims = new IirClaims(Guid.NewGuid(), Utility.ToTimestamp(now), key.Public, cap, principles);
            iir.Signature = Crypto.GenerateSignature(iir.Encode(), key);
            return iir;
        }

        public void Verify()
        {
            Verify(Key.FromBase58Key(PublicKey));
        }

        public override void Verify(Key key)
        {
            if (DateTime.UtcNow < IssuedAt) { throw new DateExpirationException("An identity issuing request cannot have an issued at date in the future."); }
            base.Verify(key);
        }

        public bool WantsCapability(Capability capability)
        {
            return _capabilities.Any(cap => cap == capability);
        }

        /// <summary>Issues a new signed identity from an identity issuing request (IIR). The new identity
        /// will be signed by the provided issuerIdentity. The identity of the issuer must either be trusted
        /// by the TrustedIdentity, or be the TrustedIdentity. The newly issued identity will belong to the same
        /// system specified in issuerIdentity.</summary>
        /// <param name="subjectId">The subject id that should be associated with the identity.</param>
        /// <param name="validFor">The number of seconds the identity should be valid, from issued at date, which is set automatically.</param>
        /// <param name="issuerKey">The key pair of the issuer.</param>
        /// <param name="issuerIdentity">The identity of the issuer (optional).</param>
        /// <param name="allowedCapabilities">The capabilities that are allowed to be requested in the IIR, must not be null.</param>
        /// <param name="requiredCapabilities">The capabilities that must be asked for in the IIR, may be null.</param>
        /// <param name="ambits">The areas or regions where the identity is valid.</param>
        /// <param name="methods">A list of methods that will apply to the issued identity.</param>
        /// <returns>Returns an imutable Identity instance.</returns>
        public Identity Issue(Guid subjectId, long validFor, Key issuerKey, Identity issuerIdentity, List<Capability> allowedCapabilities, List<Capability> requiredCapabilities = null, List<string> ambits = null, List<string> methods = null) 
        {    
            if (issuerIdentity == null) { throw new ArgumentNullException(nameof(issuerIdentity), "Issuer identity must not be null."); }
            return IssueNewIdentity(issuerIdentity.SystemName, subjectId, validFor, issuerKey, issuerIdentity, allowedCapabilities, requiredCapabilities, ambits, methods);
        }

        /// <summary>Issues a new self signed identity from an identity issuing request (IIR). The new identity
        /// will be signed by the provided issuerKey, which must match the public key inside the IIR.</summary>
        /// <param name="subjectId">The subject id that should be associated with the identity.</param>
        /// <param name="validFor">The number of seconds the identity should be valid, from issued at date, which is set automatically.</param>
        /// <param name="issuerKey">The key pair of the issuer.</param>
        /// <param name="systemName">An unique name of the system where the identity is deployed (system, infrastructure, application, etc.).</param>
        /// <param name="ambits">The areas or regions where the identity is valid.</param>
        /// <param name="methods">A list of methods that will apply to the issued identity.</param>
        /// <returns>Returns an imutable self-issued Identity instance.</returns>
        public Identity SelfIssue(Guid subjectId, long validFor, Key issuerKey, string systemName, List<string> ambits = null, List<string> methods = null)
        {
            if (string.IsNullOrEmpty(systemName)) { throw new ArgumentNullException(nameof(systemName), "System name must not be null or empty."); }
            return IssueNewIdentity(systemName, subjectId, validFor, issuerKey, null, null, null, ambits, methods);
        }

        internal new static IdentityIssuingRequest FromEncoded(string encoded)
        {
            var iir = new IdentityIssuingRequest();
            iir.Decode(encoded);
            return iir;
        }

        #endregion

        # region -- PROTECTED --

        protected override void Decode(string encoded) 
        {
            var components = encoded.Split(new[] { Envelope._COMPONENT_DELIMITER });
            if (components.Length != NbrComponentsWithoutSignature && components.Length != NbrComponentsWithSignature) { throw new FormatException($"Unexpected number of components for identity issuing request, expected {NbrComponentsWithoutSignature} or  {NbrComponentsWithSignature}, got {components.Length}."); }
            if (components[TagIndex] != _TAG) { throw new FormatException($"Unexpected item tag, expected: \"{_TAG}\", got \"{components[TagIndex]}\"."); }
            var json = Utility.FromBase64(components[ClaimsIndex]);
            _claims = JsonSerializer.Deserialize<IirClaims>(json);
            _capabilities = new List<string>(_claims.cap).ConvertAll(str => {
                Enum.TryParse<Capability>(str, true, out var cap); return cap; });
            if (components.Length == NbrComponentsWithSignature)
            {
                Encoded = encoded.Substring(0, encoded.LastIndexOf(Envelope._COMPONENT_DELIMITER));
                Signature = components[SignatureIndex];
            }
        }

        protected override string Encode()
        {
            if (Encoded != null) return Encoded;
            StringBuilder builder = new StringBuilder();
            builder.Append(_TAG);
            builder.Append(Envelope._COMPONENT_DELIMITER);
            builder.Append(Utility.ToBase64(JsonSerializer.Serialize(_claims)));
            Encoded = builder.ToString();
            return Encoded;
        }

        #endregion

        #region -- PRIVATE --
        
        private const int NbrComponentsWithoutSignature = 2;
        private const int NbrComponentsWithSignature = 3;
        private const int TagIndex = 0;
        private const int ClaimsIndex = 1;
        private const int SignatureIndex = 2;

        private IirClaims _claims;
        private List<Capability> _capabilities { get; set; }

        private struct IirClaims
        {
            public Guid uid { get; set; }
            public string iat { get; set; }
            public string pub { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public Dictionary<string, object> pri {get; set; }

            [JsonConstructor]
            public IirClaims(Guid uid, string iat, string pub, string[] cap, Dictionary<string, object>pri)
            {
                this.uid = uid;
                this.iat = iat;
                this.pub = pub;
                this.cap = cap;
                this.pri = pri;
            }
        }
        
        private Identity IssueNewIdentity(string systemName, Guid subjectId, long validFor, Key issuerKey, Identity issuerIdentity, List<Capability> allowedCapabilities, List<Capability> requiredCapabilities = null, List<string> ambits = null, List<string> methods = null)
        {
            Verify();
            var isSelfSign = (issuerIdentity == null || PublicKey == issuerKey.Public);
            CompleteCapabilities(allowedCapabilities, requiredCapabilities, isSelfSign);
            if (!isSelfSign && !issuerIdentity.HasCapability(Capability.Issue))
                throw new IdentityCapabilityException("Issuing identity missing 'issue' capability.");
            var now = DateTime.UtcNow;
            var expires = now.AddSeconds(validFor);
            var issuerId = issuerIdentity?.SubjectId ?? subjectId;
            var identity = new Identity(systemName, subjectId, PublicKey, now, expires, issuerId, _capabilities, Principles, ambits, methods);
            if (Identity.TrustedIdentity != null && issuerIdentity != null && issuerIdentity.SubjectId != Identity.TrustedIdentity.SubjectId)
            {
                issuerIdentity.VerifyTrust();
                // The chain will only be set if this is not the trusted identity (and as long as one is set)
                identity.TrustChain = issuerIdentity;
            }
            identity.Sign(issuerKey);
            return identity;
        }

        private void CompleteCapabilities(List<Capability> allowedCapabilities, IReadOnlyCollection<Capability> requiredCapabilities, bool isSelfSign)
        {
            _capabilities ??= new List<Capability> {Capability.Generic};
            if (_capabilities.Count == 0) { _capabilities.Add(Capability.Generic); }
            if (isSelfSign)
            {
                if (!WantsCapability(Capability.Self))
                {
                    _capabilities.Add(Capability.Self);
                }
            }
            else 
            {
                if (allowedCapabilities == null || allowedCapabilities.Count == 0) { throw new ArgumentException("Allowed capabilities must be defined to issue identity.", nameof(allowedCapabilities)); }
                if (_capabilities.Except(allowedCapabilities).Any()) { throw new IdentityCapabilityException("IIR contains one or more disallowed capabilities."); }
                if (requiredCapabilities != null && requiredCapabilities.Except(_capabilities).Any()) { throw new IdentityCapabilityException("IIR is missing one or more required capabilities."); }
            }
        }

        #endregion

    }

}