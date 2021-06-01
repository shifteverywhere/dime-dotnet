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
        
        public Identity() { }
        
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
            if (Dime.GetType(encoded) != typeof(Identity)) { throw new DataFormatException("Invalid header."); }
            string[] components = encoded.Split(new char[] { Identity._MAIN_DELIMITER });
            if (components.Length != 3 && components.Length != 4) { throw new ArgumentException("Unexpected number of components found then decoding identity."); }
            ProfileVersion profile;
            Enum.TryParse<ProfileVersion>(components[0].Substring(1), true, out profile);
            this.Profile = profile;
            if (!Crypto.SupportedProfile(this.Profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] json = Utility.FromBase64(components[1]);
            this._claims = JsonSerializer.Deserialize<IdentityClaims>(json);
            this._capabilities = new List<string>(this._claims.cap).ConvertAll(str => { Capability cap; Enum.TryParse<Capability>(str, true, out cap); return cap; });
            if (components.Length == 4)
            {
                byte[] issIdentity = Utility.FromBase64(components[2]);
                this.TrustChain = Dime.Import<Identity>(System.Text.Encoding.UTF8.GetString(issIdentity, 0, issIdentity.Length));
            }
            this._encoded = encoded.Substring(0, encoded.LastIndexOf(Identity._MAIN_DELIMITER));
            this._signature = components[components.Length - 1];
        }

        protected override string Encode()
        {
            if (this._encoded == null) 
            {  
                StringBuilder builder = new StringBuilder();
                builder.Append('I'); // The header of a DiME identity
                builder.Append((int)this.Profile);
                builder.Append(Dime._MAIN_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                if (this.TrustChain != null)
                {
                    builder.Append(Dime._MAIN_DELIMITER);
                    builder.Append(Utility.ToBase64(this.TrustChain.Export()));
                }
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

        #region -- PRIVATE --

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
