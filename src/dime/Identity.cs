//
//  Identity.cs
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
using System.Collections.ObjectModel;

namespace ShiftEverywhere.DiME
{
    ///<summary>Represents a digital identity of an entity. Can be self-signed or signed by a trusted identity (and thus
    /// be part of a trust chain.</summary>
    public class Identity: Item
    {
        #region -- PUBLIC --

        ///<summary>A shared trusted identity that acts as the root identity in the trust chain.</summary>
        public static Identity TrustedIdentity { get { lock(Identity._lock) { return Identity._trustedIdentity; } } }
        public const string TAG = "ID";
        public override string Tag { get { return Identity.TAG; } }
        public override Guid UniqueId { get { return this._claims.uid; } }
        /// <summary>A unique UUID (GUID) of the identity. Same as the "sub" field.</summary>
        public Guid SubjectId { get { return this._claims.sub; } }        
        /// <summary>The date when the identity was issued, i.e. approved by the issuer. Same as the "iat" field.</summary>
        public long IssuedAt { get { return this._claims.iat; } }
        /// <summary>The date when the identity will expire and should not be accepted anymore. Same as the "exp" field.</summary>
        public long ExpiresAt { get { return this._claims.exp; } } 
        /// <summary>A unique UUID (GUID) of the issuer of the identity. Same as the "iss" field. If same value as subjectId, then this is a self-issued identity.</summary>
        public Guid IssuerId { get { return this._claims.iss; } }
        /// <summary>The public key associated with the identity. Same as the "iky" field.</summary>
        public string PublicKey { get { return this._claims.pub; } }
        /// <summary>The trust chain of signed public keys.</summary>
        public Identity TrustChain { get; internal set; }
        public ReadOnlyDictionary<string, dynamic> Principles { get; private set; }
        public IList<string> Ambits { get; private set; }

        public bool IsSelfSigned { get { return (this.SubjectId == this.IssuerId && this.HasCapability(Capability.Self)); } }

        ///<summary>Set the shared trusted identity, which forms the basis of the trust chain. All identities will be verified
        /// from a trust perspecitve using this identity. For the trust chain to hold, then all identities must be either issued
        /// by this identity or other identities (with the 'issue' capability) that has been issued by this identity.
        ///<param name="identity">The identity to set as the trusted identity.</param>
        public static void SetTrustedIdentity(Identity identity)
        {
            lock(Identity._lock)
            {
                Identity._trustedIdentity = identity;
            }
        }

        public Identity() { }

        public void VerifyTrust()
        {
            if (Identity.TrustedIdentity == null) { throw new InvalidOperationException("Unable to verify trust, no trusted identity set."); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (this.IssuedAt > now) { throw new DateExpirationException("Identity is not yet valid, issued at date in the future."); }
            if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Invalid expiration date, expires at before issued at."); }
            if (this.ExpiresAt < now) { throw new DateExpirationException("Identity has expired."); }
            if (this.TrustChain != null)
            {
                this.TrustChain.VerifyTrust();
            } 
            string publicKey = this.TrustChain != null ? this.TrustChain.PublicKey : Identity.TrustedIdentity.PublicKey;
            try {
                Crypto.VerifySignature(this._encoded, this._signature, KeyBox.FromBase58Key(publicKey));
            } catch (IntegrityException) 
            {
                throw new UntrustedIdentityException("Identity cannot be trusted.");
            }
        }

        /// <summary>Will check if the identity has a specific capability.</summary>
        /// <param name="capability">The capability to check for.</param>
        /// <returns>Boolean to indicate if the identity has the capability or not.</returns>
        public bool HasCapability(Capability capability)
        {
            return this._capabilities.Any(cap => cap == capability);
        }

        internal new static Identity FromEncoded(string encoded)
        {
            Identity identity = new Identity();
            identity.Decode(encoded);
            return identity;
        }

        #endregion

        #region -- INTERNAL --

        internal Identity(Guid subjectId, string publicKey, long issuedAt, long expiresAt, Guid issuerId, List<Capability> capabilities, Dictionary<string, dynamic> principles, string[] ambits) 
        {
            this._capabilities = capabilities;
            string[] cap = capabilities.ConvertAll(c => c.ToString().ToLower()).ToArray();
            this._claims = new IdentityClaims(Guid.NewGuid(), subjectId, issuerId, issuedAt, expiresAt, publicKey, cap, principles, ambits);
            if (ambits != null)
                this.Ambits = new List<string>(ambits).AsReadOnly();
        }

        protected override void Decode(string encoded) 
        {
            string[] components = encoded.Split(new char[] { Envelope._COMPONENT_DELIMITER });
            if (components.Length != Identity._NBR_EXPECTED_COMPONENTS_MIN &&
                components.Length != Identity._NBR_EXPECTED_COMPONENTS_MAX) { throw new FormatException($"Unexpected number of components for identity issuing request, expected {Identity._NBR_EXPECTED_COMPONENTS_MIN} OR {Identity._NBR_EXPECTED_COMPONENTS_MAX}, got {components.Length}."); }
            if (components[Identity._TAG_INDEX] != Identity.TAG) { throw new FormatException($"Unexpected item tag, expected: \"{Identity.TAG}\", got \"{components[Identity._TAG_INDEX]}\"."); }
            byte[] json = Utility.FromBase64(components[Identity._CLAIMS_INDEX]);
            this._claims = JsonSerializer.Deserialize<IdentityClaims>(json);
            if (this._claims.pri != null)
                this.Principles = new ReadOnlyDictionary<string, dynamic>(this._claims.pri);
            if (this._claims.amb != null)
                this.Ambits = new List<string>(this._claims.amb);
            this._capabilities = new List<string>(this._claims.cap).ConvertAll(str => { Capability cap; Enum.TryParse<Capability>(str, true, out cap); return cap; });
            if (components.Length == Identity._NBR_EXPECTED_COMPONENTS_MAX) // There is also a trust chain identity 
            {
                byte[] issIdentity = Utility.FromBase64(components[Identity._CHAIN_INDEX]);
                this.TrustChain = Identity.FromEncoded(System.Text.Encoding.UTF8.GetString(issIdentity, 0, issIdentity.Length));
            }
            this._encoded = encoded.Substring(0, encoded.LastIndexOf(Envelope._COMPONENT_DELIMITER));
            this._signature = components[components.Length - 1];
        }

        protected override string Encode()
        {
            if (this._encoded == null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(Identity.TAG);
                builder.Append(Envelope._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                if (this.TrustChain != null)
                {
                    builder.Append(Envelope._COMPONENT_DELIMITER);
                    builder.Append(Utility.ToBase64($"{this.TrustChain.Encode()}{Envelope._COMPONENT_DELIMITER}{this.TrustChain._signature}"));
                }
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

        # region -- PROTECTED --

        #endregion

        #region -- PRIVATE --

        private const int _NBR_EXPECTED_COMPONENTS_MIN = 3;
        private const int _NBR_EXPECTED_COMPONENTS_MAX = 4;
        private const int _TAG_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;
        private const int _CHAIN_INDEX = 2;
        private IdentityClaims _claims;
        private List<Capability> _capabilities { get; set; }
        private static readonly object _lock = new object();
        private static Identity _trustedIdentity;

        private struct IdentityClaims
        {
            public Guid uid { get; set; }
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }
            public string pub { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public Dictionary<string, dynamic> pri { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] amb { get; set; }

            [JsonConstructor]
            public IdentityClaims(Guid uid, Guid sub, Guid iss, long iat, long exp, string pub, string[] cap, Dictionary<string, dynamic> pri, string[] amb)
            {
                this.uid = uid;
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
                this.pub = pub;
                this.cap = cap;
                this.pri = pri;
                this.amb = amb;
            }
        }
        
        #endregion

    }
}
