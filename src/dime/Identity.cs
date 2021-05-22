using System;
using System.Text;
using System.Text.Json;

namespace ShiftEverywhere.DiME
{
    public class Identity
    {
        /* PUBLIC */
        public static Identity trustedIdentity;
        /// <summary>The cryptography profile that is used with the identity.</summary>
        public int profile { get; private set; }
        /// <summary>A unique UUID (GUID) of the identity. Same as the "sub" field.</summary>
        public Guid subjectId { get { return this.json.sub; } }        
        /// <summary>The date when the identity was issued, i.e. approved by the issuer. Same as the "iat" field.</summary>
        public long issuedAt { get { return this.json.iat; } }
        /// <summary>The date when the identity will expire and should not be accepted anymore. Same as the "exp" field.</summary>
        public long expiresAt { get { return this.json.exp; } } 
        /// <summary>A unique UUID (GUID) of the issuer of the identity. Same as the "iss" field. If same value as subjectId, then this is a self-issued identity.</summary>
        public Guid issuerId { get { return this.json.iss; } }
        /// <summary>The public key associated with the identity. Same as the "iky" field.</summary>
        public string identityKey { get { return this.json.iky; } }
        /// <summary>The trust chain of signed public keys.</summary>
        public Identity[] trustChain { get; private set; }

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
            //identity.isImmutable = true;
            return identity;
        }

        public string Export() 
        {
            return Encode() + "." + this.signature;
        }

        public static Identity IssueIdentity(string iir, Guid subjectId, Keypair issuerKeypair, Identity issuerIdentity = null)
        {
            return Identity.IssueIdentity(IdentityIssuingRequest.Import(iir), subjectId, issuerKeypair, issuerIdentity);
        }

        public static Identity IssueIdentity(IdentityIssuingRequest iir, Guid subjectId, Keypair issuerIdentityKeypair, Identity issuerIdentity = null) 
        {    
            iir.Verify();
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Guid issuerId = issuerIdentity != null ? issuerIdentity.subjectId : subjectId;
            Identity identity = new Identity(subjectId, iir.identityKey, now, now + Identity.defaultLifetime, issuerId, iir.profile);
            identity.signature = Crypto.GenerateSignature(identity.profile, identity.Encode(), issuerIdentityKeypair.privateKey);
            // TODO: set the chain
            return identity;
        }

        public string Thumbprint() 
        {
            return Crypto.GenerateHash(this.profile, Encode());
        }

        public bool IsSelfSigned() 
        {
            if ( this.subjectId != this.issuerId) { return false; }
            try {
                Crypto.VerifySignature(this.profile, this.Encode(), this.signature, this.identityKey);
            } catch (IntegrityException)
            {
                return false;
            }
            return true;
        }

        public void VerifyTrust()
        {
            if (Identity.trustedIdentity == null) { throw new ArgumentNullException("No trusted identity set."); }
            try {
                Crypto.VerifySignature(this.profile, this.Encode(), this.signature, Identity.trustedIdentity.identityKey);
            } catch (IntegrityException) 
            {
                throw new UntrustedIdentityException();
            }
        }

        /* PRIVATE */
        private const string HEADER = "I";
        private const long defaultLifetime = 365 * 24 * 60 * 60;
        private string signature;
        private string encoded;
        private struct JSONData
        {
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }
            public string iky { get; set; }

            public JSONData(Guid sub, Guid iss, long iat, long exp, string iky)
            {
                if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp) { throw new ArgumentException("Expiration must be in the future."); }
                if (iat > exp) { throw new ArgumentException("Expiration must be after issue date."); }
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
                this.iky = iky;
            }
        }
        private Identity.JSONData json;

        private Identity(Guid subjectId, string identityKey, long issuedAt, long expiresAt, Guid issuerId, int profile = Crypto.DEFUALT_PROFILE) 
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            this.profile = profile;
            this.json = new Identity.JSONData(subjectId, issuerId, issuedAt, expiresAt, identityKey);
        }

        private Identity(Identity.JSONData parameters, string signature = null, int profile = Crypto.DEFUALT_PROFILE) 
        {
            this.profile = profile;
            this.json = parameters;
            this.signature = signature;
        }

        private string Encode()
        {
            if ( this.encoded == null ) 
            {  
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                    Identity.HEADER,
                                    this.profile, 
                                    Utility.ToBase64(JsonSerializer.Serialize(this.json)));
                this.encoded = builder.ToString();
            }
            return this.encoded;
        }

    }
}
