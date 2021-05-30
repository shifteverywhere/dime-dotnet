using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;
using System.Collections.Generic;

namespace ShiftEverywhere.DiME
{
    public class Identity: Dime
    {
        #region -- PUBLIC --
        public static Identity TrustedIdentity; // TODO: make this thread safe
        /// <summary>The cryptography profile that is used with the identity.</summary>
        //public int Profile { get; private set; }
        /// <summary>A unique UUID (GUID) of the identity. Same as the "sub" field.</summary>
        public Guid SubjectId { get { return this._data.sub; } }        
        /// <summary>The date when the identity was issued, i.e. approved by the issuer. Same as the "iat" field.</summary>
        public long IssuedAt { get { return this._data.iat; } }
        /// <summary>The date when the identity will expire and should not be accepted anymore. Same as the "exp" field.</summary>
        public long ExpiresAt { get { return this._data.exp; } } 
        /// <summary>A unique UUID (GUID) of the issuer of the identity. Same as the "iss" field. If same value as subjectId, then this is a self-issued identity.</summary>
        public Guid IssuerId { get { return this._data.iss; } }
        /// <summary>The public key associated with the identity. Same as the "iky" field.</summary>
        public string IdentityKey { get { return this._data.iky; } }
        /// <summary>The trust chain of signed public keys.</summary>
        public Identity TrustChain { get; internal set; }
        /// <summary>Imports an identity from a DiME encoded string.</summary>
        /// <param name="encoded">A DiME encoded string.</param>
        /// <returns>Returns an imutable Identity instance.</returns>
        
        public Identity() { }
        
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

        public bool HasCapability(Capability capability)
        {
            return this._capabilities.Any(cap => cap == capability);
        }

        #endregion

        #region -- INTERNAL --
        internal Identity(Guid subjectId, string identityKey, long issuedAt, long expiresAt, Guid issuerId, List<Capability> capabilities, int profile = Crypto.DEFUALT_PROFILE) 
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            this.Profile = profile;
            this._capabilities = capabilities;
            string[] cap = capabilities.ConvertAll(c => c.ToString().ToLower()).ToArray();
            this._data = new Identity.IdentityData(subjectId, issuerId, issuedAt, expiresAt, identityKey, cap);
            
        }

        #endregion

        #region -- PROTECTED --

        protected override void Populate(string encoded) 
        {
            if (Dime.GetType(encoded) != typeof(Identity)) { throw new DataFormatException("Invalid header."); }
            string[] components = encoded.Split(new char[] { Identity._MAIN_DELIMITER });
            if (components.Length != 3 && components.Length != 4) { throw new ArgumentException("Unexpected number of components found then decoding identity."); }
            this.Profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(this.Profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] json = Utility.FromBase64(components[1]);
            this._data = JsonSerializer.Deserialize<Identity.IdentityData>(json);
            this._capabilities = new List<string>(this._data.cap).ConvertAll(str => { Capability cap; Enum.TryParse<Capability>(str, true, out cap); return cap; });
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
                builder.Append(this.Profile);
                builder.Append(Dime._MAIN_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._data)));
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

        private List<Capability> _capabilities { get; set; }
        private struct IdentityData
        {
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }
            public string iky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }

            [JsonConstructor]
            public IdentityData(Guid sub, Guid iss, long iat, long exp, string iky, string[] cap = null)
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
        private Identity.IdentityData _data;
        
        #endregion

    }
}
