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

namespace ShiftEverywhere.DiME
{
    ///<summary>Represents a digital identity of an entity. Can be self-signed or signed by a trusted identity (and thus
    /// be part of a trust chain.</summary>
    public class Identity: Dime
    {
        #region -- PUBLIC --

        public const string ITID = "aW8uZGltZWZvcm1hdC5pZA"; // base64 of io.dimeformat.id

        public override Guid Id { get { return this._claims.uid; } }
        /// <summary>A unique UUID (GUID) of the identity. Same as the "sub" field.</summary>
        public Guid SubjectId { get { return this._claims.sub; } }        
        /// <summary>The date when the identity was issued, i.e. approved by the issuer. Same as the "iat" field.</summary>
        public long IssuedAt { get { return this._claims.iat; } }
        /// <summary>The date when the identity will expire and should not be accepted anymore. Same as the "exp" field.</summary>
        public long ExpiresAt { get { return this._claims.exp; } } 
        /// <summary>A unique UUID (GUID) of the issuer of the identity. Same as the "iss" field. If same value as subjectId, then this is a self-issued identity.</summary>
        public Guid IssuerId { get { return this._claims.iss; } }
        /// <summary>The public key associated with the identity. Same as the "iky" field.</summary>
        public string IdentityKey { get { return this._claims.iky; } }
        /// <summary>The trust chain of signed public keys.</summary>
        public Identity TrustChain { get; internal set; }

        public bool IsSelfSigned { get { return (this.SubjectId == this.IssuerId && this.HasCapability(Capability.Self)); } }

        public Identity() { }

        public void Verify()
        {
            if (Dime.TrustedIdentity == null) { throw new UntrustedIdentityException("No trusted identity set."); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (this.IssuedAt > now) { throw new DateExpirationException("Identity is not yet valid, issued at date in the future."); }
            if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Invalid expiration date, expires at before issued at."); }
            if (this.ExpiresAt < now) { throw new DateExpirationException("Identity has expired."); }
            if (this.TrustChain != null)
            {
                this.TrustChain.Verify();
            } 
            string publicKey = this.TrustChain != null ? this.TrustChain.IdentityKey : Dime.TrustedIdentity.IdentityKey;
            try {
                Crypto.VerifySignature(this.Profile, this._encoded, this._signature, publicKey);
            } catch (IntegrityException) 
            {
                throw new UntrustedIdentityException();
            }
        }

        /// <summary>Will check if the identity has a specific capability.</summary>
        /// <param name="capability">The capability to check for.</param>
        /// <returns>Boolean to indicate if the identity has the capability or not.</returns>
        public bool HasCapability(Capability capability)
        {
            return this._capabilities.Any(cap => cap == capability);
        }

        #endregion

        #region -- INTERNAL --
        internal Identity(Guid subjectId, string identityKey, long issuedAt, long expiresAt, Guid issuerId, List<Capability> capabilities, ProfileVersion profile = Crypto.DEFUALT_PROFILE) 
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            this._capabilities = capabilities;
            string[] cap = capabilities.ConvertAll(c => c.ToString().ToLower()).ToArray();
            this._claims = new IdentityClaims((int)profile, Guid.NewGuid(), subjectId, issuerId, issuedAt, expiresAt, identityKey, cap);
            this.Profile = profile;
        }

        internal override void Populate(string encoded) 
        {
            string[] components = encoded.Split(new char[] { Dime._COMPONENT_DELIMITER });
            if (components.Length != Identity._NBR_EXPECTED_COMPONENTS_MIN &&
                components.Length != Identity._NBR_EXPECTED_COMPONENTS_MAX) { throw new DataFormatException($"Unexpected number of components for identity issuing request, expected {Identity._NBR_EXPECTED_COMPONENTS_MIN} OR {Identity._NBR_EXPECTED_COMPONENTS_MAX}, got {components.Length}."); }
            if (components[Identity._IDENTIFIER_INDEX] != Identity.ITID) { throw new DataFormatException($"Unexpected object identifier, expected: \"{Identity.ITID}\", got \"{components[Identity._IDENTIFIER_INDEX]}\"."); }
            byte[] json = Utility.FromBase64(components[Identity._CLAIMS_INDEX]);
            this._claims = JsonSerializer.Deserialize<IdentityClaims>(json);
            this.Profile = (ProfileVersion)this._claims.ver;
            this._capabilities = new List<string>(this._claims.cap).ConvertAll(str => { Capability cap; Enum.TryParse<Capability>(str, true, out cap); return cap; });
            if (components.Length == Identity._NBR_EXPECTED_COMPONENTS_MAX) // There is also a trust chain identity 
            {
                byte[] issIdentity = Utility.FromBase64(components[Identity._CHAIN_INDEX]);
                this.TrustChain = Dime.Import<Identity>(System.Text.Encoding.UTF8.GetString(issIdentity, 0, issIdentity.Length));
            }
            this._encoded = encoded.Substring(0, encoded.LastIndexOf(Dime._COMPONENT_DELIMITER));
            this._signature = encoded.Substring(encoded.LastIndexOf(Dime._COMPONENT_DELIMITER) + 1);
        }

        internal override string Encoded(bool includeSignature = false)
        {
            if (this._encoded == null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(Identity.ITID);
                builder.Append(Dime._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                if (this.TrustChain != null)
                {
                    builder.Append(Dime._COMPONENT_DELIMITER);
                    builder.Append(Utility.ToBase64(this.TrustChain.Encoded(true)));
                }
                this._encoded = builder.ToString();
            }
            return (includeSignature) ? $"{this._encoded}{Dime._COMPONENT_DELIMITER}{this._signature}" : this._encoded;
        }

        internal void Seal(string privateKey)
        {
            if (this._signature == null)
            {
                if (privateKey == null) { throw new ArgumentNullException(nameof(privateKey), "Private key for signing cannot be null."); }
                this._signature = Crypto.GenerateSignature(this.Profile, this.Encoded(), privateKey);
            }
        }

        #endregion

        #region -- PRIVATE --

        private const int _NBR_EXPECTED_COMPONENTS_MIN = 3;
        private const int _NBR_EXPECTED_COMPONENTS_MAX = 4;
        private const int _IDENTIFIER_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;
        private const int _CHAIN_INDEX = 2;
        private IdentityClaims _claims;
        private List<Capability> _capabilities { get; set; }

        private string _encoded;
        private string _signature;

        private struct IdentityClaims
        {
            public int ver { get; set; }
            public Guid uid { get; set; }
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }
            public string iky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }

            [JsonConstructor]
            public IdentityClaims(int ver, Guid uid, Guid sub, Guid iss, long iat, long exp, string iky, string[] cap = null)
            {
                this.ver = ver;
                this.uid = uid;
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
                this.iky = iky;
                this.cap = cap;
            }
        }
        
        #endregion

    }
}
