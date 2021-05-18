using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public class IdentityIssuingRequest
    {
        /* PUBLIC */
        /// <summary>The version of the identity format. Same as the "ver" field.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public int profile {get; private set; }
        /// <summary>The signature of the identity. Same as the "sig" field.</summary>
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public string signature { get; private set; }
        /// <summary>The date when the identity was issued, i.e. approved by the issuer. Same as the "iat" field.</summary>
        [JsonPropertyName("iat")]
        public long issuedAt { get; private set; } = 0;
        /// <summary>The public key associated with the identity. Same as the "pub" field.</summary>
        [JsonPropertyName("iky")]
        public string identityKey { get; private set; }

        public static IdentityIssuingRequest GenerateRequest(Keypair keypair, int profile = Crypto.DEFUALT_PROFILE) 
        {
            if ( !Crypto.SupportedProfile(profile) ) { throw new NotSupportedException(); }
            if ( keypair.type != KeypairType.IdentityKey ) { throw new ArgumentNullException("KeyPair of invalid type."); }
            if ( keypair.privateKey == null ) { throw new ArgumentNullException("Private key must not be null"); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            IdentityIssuingRequest iir = new IdentityIssuingRequest(now, keypair, profile);
            iir.signature = Crypto.GenerateSignature(profile, iir.Encode(), keypair.privateKey);
            return iir;
        }

        [JsonConstructor]
        public IdentityIssuingRequest(long issuedAt, string identityKey)
        {
            this.issuedAt = issuedAt;
            this.identityKey = identityKey;
            this.profile = Crypto.DEFUALT_PROFILE;
        }

        public static IdentityIssuingRequest Import(string encoded) 
        {
            if ( !encoded.StartsWith(IdentityIssuingRequest.HEADER) ) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(".");
            if ( components.Length != 3 ) { throw new ArgumentException("Unexpected number of components found then decoding identity issuing request."); }
            int profile = int.Parse(components[0].Substring(1));
            if ( !Crypto.SupportedProfile(profile) ) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] json = Utility.FromBase64(components[1]);
            IdentityIssuingRequest iir = JsonSerializer.Deserialize<IdentityIssuingRequest>(json);
            iir.profile = profile;
            iir.signature = components[2];
            iir.encoded = encoded.Substring(0, encoded.LastIndexOf('.'));
            return iir;
        }

        public string Export() 
        {
             return this.Encode() + "." + this.signature;
        }

        public string Thumbprint() 
        {
            return Crypto.GenerateHash(this.profile, this.Encode());
        }

        public bool Verify()
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now >= this.issuedAt)
            {
                return Crypto.VerifySignature(this.profile, this.Encode(), this.signature, this.identityKey);
            }
            return false;
        }

        /* PRIVATE */
        private const string HEADER = "i";
        private string encoded;

        private IdentityIssuingRequest(long issuedAt, Keypair keypair, int version = Crypto.DEFUALT_PROFILE) 
        {
            if ( keypair.publicKey == null ) { throw new ArgumentNullException("Public key must not be null"); }
            this.issuedAt = issuedAt;
            this.identityKey = keypair.publicKey;
            this.profile = version;
        }

        private string Encode()
        {
            if ( this.encoded == null ) 
            { 
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                        IdentityIssuingRequest.HEADER,
                                        this.profile, 
                                        Utility.ToBase64(JsonSerializer.Serialize(this)));
                this.encoded = builder.ToString();
            }
            return this.encoded;
        }


    }

}