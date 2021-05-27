using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;

namespace ShiftEverywhere.DiME
{
    public class Identity
    {
        #region -- PUBLIC --
        public enum Capability
        {
            Issue, Authorize, Authenticate
        }
        public const long VALID_FOR_1_YEAR = 365 * 24 * 60 * 60;
        public static Identity TrustedIdentity;
        /// <summary>The cryptography profile that is used with the identity.</summary>
        public int Profile { get; private set; }
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
        public Identity TrustChain { get; private set; }
        /// <summary>const string to improve performance</summary>
        public const string delimiter = ".";

        #region -- Import/Export --
        /// <summary>Imports an identity from a DiME encoded string.</summary>
        /// <param name="encoded">A DiME encoded string.</param>
        /// <returns>Returns an imutable Identity instance.</returns>
        public static Identity Import(string encoded) 
        {
            if (!encoded.StartsWith(Identity._HEADER)) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { '.' });
            if (components.Length != 3) { throw new ArgumentException("Unexpected number of components found then decoding identity."); }
            int profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] json = Utility.FromBase64(components[1]);
            Identity.InternalData parameters = JsonSerializer.Deserialize<Identity.InternalData>(json);
            Identity identity = new Identity(parameters, components[components.Length - 1], profile);
            identity._encoded = encoded.Substring(0, encoded.LastIndexOf('.'));
            identity._signature = components[components.Length - 1];
            return identity;
        }

        /// <summary>Exports an identity to a DiME encoded string.</summary>
        /// <returns>A DiME encoded sting of the identity.</returns>
        public string Export() 
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Encode());
            sb.Append(delimiter);
            sb.Append(_signature);

            return sb.ToString();
        }

        #endregion
        #region -- Issuing --
        /// <summary>Issues a new signed identity from an identity issuing request (IIR). The new identity
        /// will be signed by the provided issuerIdentity. The identity of the issuer must either be trusted
        /// by the TrustedIdentity, or be the TrustedIdentity. If the issuerIdentity is omitted, then the 
        /// returned identity will be self-signed. </summary>
        /// <param name="irr">The IIR from the subject.</param>
        /// <param name="subjectId">The subject id that should be associated with the identity.</param>
        /// <param name="allowedCapabilities">The capabilities allowed for the to be issued identity.</param>
        /// <param name="issuerKeypair">The key pair of the issuer.</param>
        /// <param name="issuerIdentitys">The identity of the issuer (optional).</param>
        /// <returns>Returns an imutable Identity instance.</returns>
        public static Identity Issue(string iir, Guid subjectId, Identity.Capability[] allowedCapabilities, long validFor, Keypair issuerKeypair, Identity issuerIdentity)
        {
            return Identity.Issue(IdentityIssuingRequest.Import(iir), subjectId, allowedCapabilities, validFor, issuerKeypair, issuerIdentity);
        }

        public static Identity Issue(IdentityIssuingRequest iir, Guid subjectId, Identity.Capability[] allowedCapabilities, long validFor, Keypair issuerKeypair, Identity issuerIdentity) 
        {    
            if (allowedCapabilities == null) {
                allowedCapabilities = new Identity.Capability[] { Identity.Capability.Authorize };
            }
            iir.Verify(allowedCapabilities);
            if (issuerIdentity == null || issuerIdentity.HasCapability(Identity.Capability.Issue))
            {
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                Guid issuerId = issuerIdentity != null ? issuerIdentity.SubjectId : subjectId;
                Identity identity = new Identity(subjectId, iir.IdentityKey, now, (now + validFor), issuerId, iir.capabilities, iir.Profile);
                if (Identity.TrustedIdentity != null && issuerIdentity != null && issuerIdentity.SubjectId != Identity.TrustedIdentity.SubjectId)
                {
                    issuerIdentity.VerifyTrust();
                    // The chain will only be set if this is not the trusted identity (and as long as one is set)
                    identity.TrustChain = issuerIdentity;
                }
                identity._signature = Crypto.GenerateSignature(identity.Profile, identity.Encode(), issuerKeypair.PrivateKey);
                return identity;
            }
            throw new IdentityCapabilityException("Issuing identity missing 'issue' capability.");
        }
        
        #endregion
        #region -- Public support --

        public string Thumbprint() 
        {
            return Crypto.GenerateHash(this.Profile, Encode());
        }

        public bool IsSelfSigned() 
        {
            if ( this.SubjectId != this.IssuerId) { return false; }
            try {
                Verify(this.IdentityKey);
            } catch (UntrustedIdentityException)
            {
                return false;
            }
            return true;
        }

        public void VerifyTrust()
        {
            if (this.SubjectId == this.IssuerId) { throw new UntrustedIdentityException("Identity is self-signed."); }
            if (Identity.TrustedIdentity == null) { throw new ArgumentNullException("Identity.TrustedIdentity", "No trusted identity set."); }
            if (this.TrustChain != null)
            {
                this.TrustChain.VerifyTrust();
            } 
            string publicKey = this.TrustChain != null ? this.TrustChain.IdentityKey : Identity.TrustedIdentity.IdentityKey;
            Verify(publicKey);
        }

        /// <summary>Helper function to quickly check if a string is potentially a DiME encoded identity object.</summary>
        /// <param name="encoded">The string to validate.</param>
        /// <returns>An indication if the string is a DiME encoded identity.</returns>
        public static bool IsEnvelope(string encoded)
        {
            return encoded.StartsWith(Identity._HEADER);
        }

        public bool HasCapability(Identity.Capability capability)
        {
            return this._data.cap.Any(s => s.ToLower().Equals(Identity.CapabilityToString(capability)));
        }
        #region -- INTERNAL --
        internal static Identity.Capability CapabilityFromString(string capability)
        {
            if (capability.Equals(Identity.InternalData.CAP_ISSUE)) { return Identity.Capability.Issue; }
            if (capability.Equals(Identity.InternalData.CAP_AUTHORIZE)) { return Identity.Capability.Authorize; }
            if (capability.Equals(Identity.InternalData.CAP_AUTHENTICATE)) { return Identity.Capability.Authenticate; }
            throw new IdentityCapabilityException("Unknown capability.");
        }

        internal static string CapabilityToString(Identity.Capability capability)
        {
            switch (capability)
            {
                case Identity.Capability.Issue: return Identity.InternalData.CAP_ISSUE;
                case Identity.Capability.Authorize: return Identity.InternalData.CAP_AUTHORIZE;
                case Identity.Capability.Authenticate: return Identity.InternalData.CAP_AUTHENTICATE;
            }
            return null;
        }
        #endregion
        #endregion
        #endregion
        #region -- PRIVATE --

        private const string _HEADER = "I";
        private string _signature;
        private string _encoded;
        private struct InternalData
        {
            public static string CAP_ISSUE = "issue";
            public static string CAP_AUTHORIZE = "authorize";
            public static string CAP_AUTHENTICATE = "authenticate";
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }
            public string iky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }

            public InternalData(Guid sub, Guid iss, long iat, long exp, string iky, string[] cap = null)
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
        private Identity.InternalData _data;

        private Identity(Guid subjectId, string identityKey, long issuedAt, long expiresAt, Guid issuerId, string[] capabilities, int profile = Crypto.DEFUALT_PROFILE) 
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            this.Profile = profile;
            this._data = new Identity.InternalData(subjectId, issuerId, issuedAt, expiresAt, identityKey, capabilities);
        }

        private Identity(Identity.InternalData parameters, string signature = null, int profile = Crypto.DEFUALT_PROFILE) 
        {
            this.Profile = profile;
            this._data = parameters;
            this._signature = signature;
        }
        
        private void Verify(string publicKey)
        {
            try 
            {
                Crypto.VerifySignature(this.Profile, Encode(), this._signature, publicKey);
            } 
            catch (IntegrityException) 
            {
                throw new UntrustedIdentityException();
            }
        }

        private string Encode()
        {
            if (this._encoded == null) 
            {  
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                    Identity._HEADER,
                                    this.Profile, 
                                    Utility.ToBase64(JsonSerializer.Serialize(this._data)));
                if (this.TrustChain != null)
                {
                    builder.AppendFormat(".{0}", Utility.ToBase64(this.TrustChain.Export()));
                }
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

    }
}
