using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public class Identity
    {
        /* PUBLIC */
        public static Identity trustedIdentity;
        /// <summary>The cryptography profile that is used with the identity.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public int profile {get; private set; } = 1;
        /// <summary>A unique UUID (GUID) of the identity. Same as the "sub" field.</summary>
        [JsonPropertyName("sub")]
        public Guid subjectId { get; private set; }        
        /// <summary>The date when the identity was issued, i.e. approved by the issuer. Same as the "iat" field.</summary>
        [JsonPropertyName("iat")]
        public long issuedAt { get; private set; } = 0;
        /// <summary>The date when the identity will expire and should not be accepted anymore. Same as the "exp" field.</summary>
        [JsonPropertyName("exp")]
        public long expiresAt { get; private set; } = 0;
        /// <summary>A unique UUID (GUID) of the issuer of the identity. Same as the "iss" field. If same value as subjectId, then this is a self-issued identity.</summary>
        [JsonPropertyName("iss")]
        public Guid issuerId { get; private set; }
        /// <summary>The public key associated with the identity. Same as the "iky" field.</summary>
        [JsonPropertyName("iky")]
        public string identityKey { get; private set; }
        /// <summary>The trust chain of signed public keys. Same as the "chn" field.</summary>
        [JsonPropertyName("chn")][JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public Identity[] trustChain { get; private set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public string signature { get; private set; }

        [JsonConstructor]
        public Identity(Guid subjectId, long issuedAt, long expiresAt, Guid issuerId, string identityKey)
        {
            this.subjectId = subjectId;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.issuerId = issuerId;
            this.identityKey = identityKey;
        }

        public Identity(Guid subjectId, string identityKey, long issuedAt, long expiresAt, Guid issuerId, string signature = null, int profile = Crypto.DEFUALT_PROFILE) 
        {
            this.profile = profile;
            this.subjectId = subjectId;
            this.identityKey = identityKey;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.issuerId = issuerId;
            this.signature = signature;
        }

        public static Identity Import(string encoded) 
        {
            if ( !encoded.StartsWith(Identity.HEADER) ) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(".");
            if ( components.Length != 3 ) { throw new ArgumentException("Unexpected number of components found then decoding identity."); }
            int profile = int.Parse(components[0].Substring(1));
            if ( !Crypto.SupportedProfile(profile) ) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] json = Utility.FromBase64(components[1]);
            Identity identity = JsonSerializer.Deserialize<Identity>(json);
            identity.profile = profile;
            identity.signature = components[2];
            identity.encoded = encoded.Substring(0, encoded.LastIndexOf('.'));
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

        public static Identity IssueIdentity(IdentityIssuingRequest iir, Guid subjectId, Keypair issuerKeypair, Identity issuerIdentity = null) 
        {    
            if ( iir.Verify() )
            {
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
                Guid issuerId = issuerIdentity != null ? issuerIdentity.subjectId : subjectId;
                Identity identity = new Identity(subjectId, iir.identityKey, now, now + Identity.defaultLifetime, issuerId);
                identity.identityKey = iir.identityKey;
                identity.signature = Crypto.GenerateSignature(identity.profile, identity.Encode(), issuerKeypair.privateKey);
                // TODO: set the chain
                return identity;
            }
            throw new ArgumentException("Unable to verify claim signature"); // TODO: throw another type of exception
        }

        public string Thumbprint() 
        {
            return Crypto.GenerateHash(this.profile, Encode());
        }

        public bool IsSelfSigned() 
        {
            if ( this.subjectId != this.issuerId) { return false; }
            return Crypto.VerifySignature(this.profile, this.Encode(), this.signature, this.identityKey);
        }

        public bool VerifyTrust()
        {
            if (Identity.trustedIdentity == null) { throw new ArgumentNullException("No trusted identity set."); }
            return Crypto.VerifySignature(this.profile, this.Encode(), this.signature, Identity.trustedIdentity.identityKey);
        }

        /* PRIVATE */
        private const string HEADER = "I";
        private const long defaultLifetime = 365 * 24 * 60 * 60;
        private string encoded;
        private string Encode()
        {
            if ( this.encoded == null ) 
            {  
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                    Identity.HEADER,
                                    this.profile, 
                                    Utility.ToBase64(JsonSerializer.Serialize(this)));
                this.encoded = builder.ToString();
            }
            return this.encoded;
        }

    }
}
