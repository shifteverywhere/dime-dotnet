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
        public Guid SubjectId { get { return this.json.sub; } }        
        /// <summary>The date when the identity was issued, i.e. approved by the issuer. Same as the "iat" field.</summary>
        public long IssuedAt { get { return this.json.iat; } }
        /// <summary>The date when the identity will expire and should not be accepted anymore. Same as the "exp" field.</summary>
        public long ExpiresAt { get { return this.json.exp; } } 
        /// <summary>A unique UUID (GUID) of the issuer of the identity. Same as the "iss" field. If same value as subjectId, then this is a self-issued identity.</summary>
        public Guid IssuerId { get { return this.json.iss; } }
        /// <summary>The public key associated with the identity. Same as the "iky" field.</summary>
        public string identityKey { get { return this.json.iky; } }
        /// <summary>The trust chain of signed public keys.</summary>
        public Identity TrustChain { get; private set; }
        public bool IsMutable { get; private set; } = true;

        #region -- Import/Export --
        /// <summary>Imports an identity from a DiME encoded string.</summary>
        /// <param name="encoded">A DiME encoded string.</param>
        /// <returns>Returns an imutable Identity instance.</returns>
        public static Identity Import(string encoded) 
        {
            if (!encoded.StartsWith(Identity.HEADER)) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { '.' });
            if (components.Length != 3) { throw new ArgumentException("Unexpected number of components found then decoding identity."); }
            int profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] json = Utility.FromBase64(components[1]);
            Identity.JSONData parameters = JsonSerializer.Deserialize<Identity.JSONData>(json);
            Identity identity = new Identity(parameters, components[components.Length - 1], profile);
            identity.encoded = encoded.Substring(0, encoded.LastIndexOf('.'));
            identity.IsMutable = false;
            return identity;
        }

        /// <summary>Exports an identity to a DiME encoded string.</summary>
        /// <returns>A DiME encoded sting of the identity.</returns>
        public string Export() 
        {
            return Encode() + "." + this.signature;
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
            if (issuerIdentity != null) { issuerIdentity.VerifyTrust(); }
            if (issuerIdentity == null || issuerIdentity.HasCapability(Identity.Capability.Issue))
            {
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                Guid issuerId = issuerIdentity != null ? issuerIdentity.SubjectId : subjectId;
                Identity identity = new Identity(subjectId, iir.IdentityKey, now, (now + validFor), issuerId, iir.capabilities, iir.Profile);
                identity.signature = Crypto.GenerateSignature(identity.Profile, identity.Encode(), issuerKeypair.PrivateKey);
                if (Identity.TrustedIdentity != null && issuerIdentity.SubjectId != Identity.TrustedIdentity.SubjectId)
                {
                    // The chain will only be set if this is not the trusted identity (and as long as one is set)
                    identity.TrustChain = issuerIdentity;
                }
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
                Crypto.VerifySignature(this.Profile, this.Encode(), this.signature, this.identityKey);
            } catch (IntegrityException)
            {
                return false;
            }
            return true;
        }

        public void VerifyTrust()
        {
            if (Identity.TrustedIdentity == null) { throw new ArgumentNullException("No trusted identity set."); }
            try 
            {
                Crypto.VerifySignature(this.Profile, this.Encode(), this.signature, Identity.TrustedIdentity.identityKey);
            } 
            catch (IntegrityException) 
            {
                throw new UntrustedIdentityException();
            }
        }

        public bool HasCapability(Identity.Capability capability)
        {
            return this.json.cap.Any(s => s.ToLower().Equals(Identity.CapabilityToString(capability)));
        }
        #region -- INTERNAL --
        internal static Identity.Capability CapabilityFromString(string capability)
        {
            if (capability.Equals(Identity.JSONData.CAP_ISSUE)) { return Identity.Capability.Issue; }
            if (capability.Equals(Identity.JSONData.CAP_AUTHORIZE)) { return Identity.Capability.Authorize; }
            if (capability.Equals(Identity.JSONData.CAP_AUTHENTICATE)) { return Identity.Capability.Authenticate; }
            throw new IdentityCapabilityException("Unknown capability.");
        }

        internal static string CapabilityToString(Identity.Capability capability)
        {
            switch (capability)
            {
                case Identity.Capability.Issue: return Identity.JSONData.CAP_ISSUE;
                case Identity.Capability.Authorize: return Identity.JSONData.CAP_AUTHORIZE;
                case Identity.Capability.Authenticate: return Identity.JSONData.CAP_AUTHENTICATE;
            }
            return null;
        }
        #endregion
        #endregion
        #endregion
        #region -- PRIVATE --

        private const string HEADER = "I";
        private string signature;
        private string encoded;
        private struct JSONData
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

            public JSONData(Guid sub, Guid iss, long iat, long exp, string iky, string[] cap = null)
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
        private Identity.JSONData json;

        private Identity(Guid subjectId, string identityKey, long issuedAt, long expiresAt, Guid issuerId, string[] capabilities, int profile = Crypto.DEFUALT_PROFILE) 
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            this.Profile = profile;
            this.json = new Identity.JSONData(subjectId, issuerId, issuedAt, expiresAt, identityKey, capabilities);
        }

        private Identity(Identity.JSONData parameters, string signature = null, int profile = Crypto.DEFUALT_PROFILE) 
        {
            this.Profile = profile;
            this.json = parameters;
            this.signature = signature;
        }

        private string Encode()
        {
            if (this.encoded == null) 
            {  
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                    Identity.HEADER,
                                    this.Profile, 
                                    Utility.ToBase64(JsonSerializer.Serialize(this.json)));
                if (this.TrustChain != null)
                {
                    builder.AppendFormat(".{0}", Utility.ToBase64(this.TrustChain.Export()));
                }
                this.encoded = builder.ToString();
            }
            return this.encoded;
        }

        #endregion

    }
}
