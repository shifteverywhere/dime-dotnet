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

        public const string Identifier = "aW8uZGltZWZvcm1hdC5pZA"; // base64 of io.dimeformat.id

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
        public Attachment Attachment { get; set; }
        
        public Identity() { }
        public override string Export() 
        {
            string encoded = base.Export();
            if (this.Attachment != null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(encoded);
                builder.Append(Dime._ATTATCHMENT_DELIMITER);
                builder.Append(this.Attachment.Export());
                return builder.ToString();
            }
            else
            {
                return encoded;
            }
        }

        /// <summary>Checks if the identity is self-signed (signed/seald by itself).</summary>
        /// <returns>Boolean to indicate if it is self-signed or not.</returns>
        public bool IsSelfSigned() 
        {
            if (this.SubjectId != this.IssuerId) { return false; }
            // TODO: get Capability.Self in here
            try {
                Verify(this.IdentityKey);
            } catch (UntrustedIdentityException)
            {
                return false;
            }
            return true;
        }

        public override void Verify()
        {
            if (this.SubjectId == this.IssuerId) { throw new UntrustedIdentityException("Identity is self-signed."); }
            if (Identity.TrustedIdentity == null) { throw new UntrustedIdentityException("No trusted identity set."); }
            // TODO: verify iat/exp
            if (this.TrustChain != null)
            {
                this.TrustChain.Verify();
            } 
            string publicKey = this.TrustChain != null ? this.TrustChain.IdentityKey : Identity.TrustedIdentity.IdentityKey;
            try {
                base.Verify(publicKey);
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
            this.Profile = profile;
            this._capabilities = capabilities;
            string[] cap = capabilities.ConvertAll(c => c.ToString().ToLower()).ToArray();
            this._claims = new IdentityClaims(subjectId, issuerId, issuedAt, expiresAt, identityKey, cap);
            
        }

        #endregion

        #region -- PROTECTED --

        protected override void Populate(string encoded) 
        {
            string[] components = encoded.Split(new char[] { Dime._COMPONENT_DELIMITER });
            if (components.Length != Identity._NBR_EXPECTED_COMPONENTS_MIN &&
                components.Length != Identity._NBR_EXPECTED_COMPONENTS_MAX) { throw new DataFormatException($"Unexpected number of components for identity issuing request, expected {Identity._NBR_EXPECTED_COMPONENTS_MIN} OR {Identity._NBR_EXPECTED_COMPONENTS_MAX}, got {components.Length}."); }
            if (components[Identity._IDENTIFIER_INDEX] != Identity.Identifier) { throw new DataFormatException($"Unexpected object identifier, expected: \"{Identity.Identifier}\", got \"{components[Identity._IDENTIFIER_INDEX]}\"."); }

            byte[] json = Utility.FromBase64(components[Identity._CLAIMS_INDEX]);
            this._claims = JsonSerializer.Deserialize<IdentityClaims>(json);
            this._capabilities = new List<string>(this._claims.cap).ConvertAll(str => { Capability cap; Enum.TryParse<Capability>(str, true, out cap); return cap; });
            if (components.Length == Identity._NBR_EXPECTED_COMPONENTS_MAX) // There is also a trust chain identity 
            {
                byte[] issIdentity = Utility.FromBase64(components[Identity._CHAIN_INDEX]);
                this.TrustChain = Dime.Import<Identity>(System.Text.Encoding.UTF8.GetString(issIdentity, 0, issIdentity.Length));
            }
        }

        protected override void Encode(StringBuilder builder)
        {
            builder.Append(Identity.Identifier);
            builder.Append(Dime._COMPONENT_DELIMITER);
            builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
            if (this.TrustChain != null)
            {
                builder.Append(Dime._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(this.TrustChain.Export()));
            }
        }

        #endregion

        #region -- PRIVATE --

        private const int _NBR_EXPECTED_COMPONENTS_MIN = 2;
        private const int _NBR_EXPECTED_COMPONENTS_MAX = 3;
        private const int _IDENTIFIER_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;
        private const int _CHAIN_INDEX = 2;

        private struct IdentityClaims
        {
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }
            public string iky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }

            [JsonConstructor]
            public IdentityClaims(Guid sub, Guid iss, long iat, long exp, string iky, string[] cap = null)
            {
                if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp) { throw new ArgumentException("Expiration must be in the future."); }
                if (iat > exp) { throw new ArgumentException("Expiration must be after issue date."); }
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
                this.iky = iky;
                this.cap = cap;
            }
        }
        private IdentityClaims _claims;
        private List<Capability> _capabilities { get; set; }
        
        #endregion

    }
}
