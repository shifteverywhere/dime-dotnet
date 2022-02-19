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
using System.Collections.Immutable;
using System.Collections.ObjectModel;

namespace DiME
{
    /// <summary>
    /// Class used to create a request for the issuing of an identity to an entity. This will contain a locally
    /// generated public key (where the private key remains locally), capabilities requested and principles claimed. An
    /// issuing entity uses the Identity Issuing Request (IIR) to validate and then issue a new identity for the entity.
    /// </summary>
    public class IdentityIssuingRequest: Item
    {
        #region -- PUBLIC --

        /// <summary>
        /// A constant holding the number of seconds for a year (based on 365 days).
        /// </summary>
        public const long _VALID_FOR_1_YEAR = 365L * 24 * 60 * 60; 
        /// <summary>
        /// A tag identifying the Di:ME item type, part of the header.
        /// </summary>
        public const string _TAG = "IIR";
        /// <summary>
        /// Returns the tag of the Di:ME item.
        /// </summary>
        public override string Tag => _TAG;
        /// <summary>
        /// Returns a unique identifier for the instance. This will be generated at instance creation.
        /// </summary>
        public override Guid UniqueId => _claims.uid;
        /// <summary>
        /// The date and time when this IIR was created.
        /// </summary>
        public DateTime IssuedAt => Utility.FromTimestamp(_claims.iat);
        /// <summary>
        /// Returns the public key attached to the IIR. This is the public key attached by the entity and will get
        /// included in any issued identity. The equivalent secret (private) key was used to sign the IIR, thus the
        /// public key can be used to verify the signature. This must be a key of type IDENTITY.
        /// </summary>
        public Key PublicKey => _claims.pub is {Length: > 0} ? Key.FromBase58Key(_claims.pub) : null;
        /// <summary>
        /// Returns all principles provided in the IIR. These are key-value fields that further provide information
        /// about the entity. Using principles are optional.
        /// </summary>
        public ReadOnlyDictionary<string, object> Principles => _claims.pri != null ? new ReadOnlyDictionary<string, object>(_claims.pri) : null;
        
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

        /// <summary>
        /// Verifies that the IIR has been signed by the secret (private) key that is associated with the public key
        /// included in the IIR. If this passes then it can be assumed that the sender is in possession of the private
        /// key used to create the IIR and will also after issuing of an identity form the proof-of-ownership.
        /// </summary>
        public void Verify()
        {
            Verify(PublicKey);
        }

        /// <summary>
        /// Verifies that the IIR has been signed by a secret (private) key that is associated with the provided public
        /// key. If this passes then it can be assumed that the sender is in possession of the private key associated
        /// with the public key used to verify. This method may be used when verifying that an IIR has been signed by
        /// the same secret key that belongs to an already issued identity, this could be useful when re-issuing an identity.
        /// </summary>
        /// <param name="key">The key that should be used to verify the IIR, must be of type IDENTITY.</param>
        /// <exception cref="DateExpirationException">If the IIR was issued in the future (according to the issued at date).</exception>
        public override void Verify(Key key)
        {
            if (DateTime.UtcNow < IssuedAt) { throw new DateExpirationException("An identity issuing request cannot have an issued at date in the future."); }
            base.Verify(key);
        }

        /// <summary>
        /// Checks if the IIR includes a request for a particular capability.
        /// </summary>
        /// <param name="capability">The capability to check for.</param>
        /// <returns>true or false.</returns>
        public bool WantsCapability(Capability capability)
        {
            return _capabilities.Any(cap => cap == capability);
        }
        
        /// <summary>
        /// Will issue a new Identity instance from the IIR. This method should only be called after the IIR has been
        /// validated to meet context and application specific requirements. The only exception is the capabilities,
        /// that may be validated during the issuing, by providing allowed and required capabilities. The system name of
        /// the issued identity will be set to the same as the issuing identity.
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
        /// <param name="ambits">A list of ambits that will apply to the issued identity.</param>
        /// <param name="methods">A list of methods that will apply to the issued identity.</param>
        /// <returns>An Identity instance that may be sent back to the entity that proved the IIR.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public Identity Issue(Guid subjectId, long validFor, Key issuerKey, Identity issuerIdentity, bool includeChain, List<Capability> allowedCapabilities, List<Capability> requiredCapabilities = null, List<string> ambits = null, List<string> methods = null) 
        {    
            if (issuerIdentity == null) { throw new ArgumentNullException(nameof(issuerIdentity), "Issuer identity must not be null."); }
            return IssueNewIdentity(issuerIdentity.SystemName, subjectId, validFor, issuerKey, issuerIdentity, includeChain, allowedCapabilities, requiredCapabilities, ambits, methods);
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
        /// <param name="ambits">A list of ambits that will apply to the issued identity.</param>
        /// <param name="methods">A list of methods that will apply to the issued identity.</param>
        /// <returns></returns>
        /// <exception cref="ArgumentNullException"></exception>
        public Identity SelfIssue(Guid subjectId, long validFor, Key issuerKey, string systemName, List<string> ambits = null, List<string> methods = null)
        {
            if (string.IsNullOrEmpty(systemName)) { throw new ArgumentNullException(nameof(systemName), "System name must not be null or empty."); }
            return IssueNewIdentity(systemName, subjectId, validFor, issuerKey, null, false, null, null, ambits, methods);
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
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)][JsonConverter(typeof(DictionaryStringObjectJsonConverter))]
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
        
        private Identity IssueNewIdentity(string systemName, Guid subjectId, long validFor, Key issuerKey, Identity issuerIdentity, bool includeChain, List<Capability> allowedCapabilities, IReadOnlyCollection<Capability> requiredCapabilities = null, List<string> ambits = null, List<string> methods = null)
        {
            Verify(PublicKey);
            var isSelfSign = issuerIdentity == null || PublicKey.Public.Equals(issuerKey.Public);
            CompleteCapabilities(allowedCapabilities, requiredCapabilities, isSelfSign);
            if (!isSelfSign && !issuerIdentity.HasCapability(Capability.Issue))
                throw new IdentityCapabilityException("Issuing identity missing 'issue' capability.");
            var now = DateTime.UtcNow;
            var expires = now.AddSeconds(validFor);
            var issuerId = issuerIdentity?.SubjectId ?? subjectId;
            var identity = new Identity(systemName, subjectId, PublicKey.Public, now, expires, issuerId, _capabilities, _claims.pri, ambits, methods);
            if (Identity.TrustedIdentity != null && issuerIdentity != null && issuerIdentity.SubjectId != Identity.TrustedIdentity.SubjectId)
            {
                issuerIdentity.IsTrusted();
                // The chain will only be set if this is not the trusted identity (and as long as one is set)
                // and if it is a trusted issuer identity (from set trusted identity) and includeChain is set to true
                if (includeChain)
                {
                    identity.TrustChain = issuerIdentity;    
                }
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