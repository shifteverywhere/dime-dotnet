using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public class IdentityIssuingRequest
    {
        /* PUBLIC */
        public int profile {get; private set; }
        public long issuedAt { get { return this.json.iat;} }
        public string identityKey { get { return this.json.iky; } }

        public static IdentityIssuingRequest GenerateRequest(Keypair keypair) 
        {
            if (keypair.type != KeypairType.IdentityKey) { throw new ArgumentNullException("KeyPair of invalid type."); }
            if (keypair.privateKey == null) { throw new ArgumentNullException("Private key must not be null"); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            IdentityIssuingRequest iir = new IdentityIssuingRequest(new IdentityIssuingRequest.JSONData(now, keypair.publicKey), keypair.profile);
            iir.signature = Crypto.GenerateSignature(iir.profile, iir.Encode(), keypair.privateKey);
            return iir;
        }

        public static IdentityIssuingRequest Import(string encoded) 
        {
            if (!encoded.StartsWith(IdentityIssuingRequest.HEADER)) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { '.' });
            if (components.Length != 3 ) { throw new ArgumentException("Unexpected number of components found then decoding identity issuing request."); }
            int profile = int.Parse(components[0].Substring(1));
            byte[] json = Utility.FromBase64(components[1]);
            IdentityIssuingRequest.JSONData parameters = JsonSerializer.Deserialize<IdentityIssuingRequest.JSONData>(json);
            IdentityIssuingRequest iir = new IdentityIssuingRequest(parameters, profile);
            iir.signature = components[2];
            iir.encoded = encoded.Substring(0, encoded.LastIndexOf('.'));
            //iir.isImmutable = true;
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

        public void Verify()
        {
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() < this.issuedAt) { throw new DateExpirationException(); }
            Crypto.VerifySignature(this.profile, this.Encode(), this.signature, this.identityKey);
        }

        /* PRIVATE */
        private const string HEADER = "i";
        private string encoded;
        private string signature;
        private struct JSONData
        {
            public long iat { get; set; }
            public string iky { get; set; }

            public JSONData(long iat, string iky)
            {
                this.iat = iat;
                this.iky = iky;
            }
        }
        private IdentityIssuingRequest.JSONData json;

        private IdentityIssuingRequest(IdentityIssuingRequest.JSONData parameters, int profile = Crypto.DEFUALT_PROFILE) 
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            this.json = parameters;
            this.profile = profile;
        }

        private string Encode()
        {
            if ( this.encoded == null ) 
            { 
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                        IdentityIssuingRequest.HEADER,
                                        this.profile, 
                                        Utility.ToBase64(JsonSerializer.Serialize(this.json)));
                this.encoded = builder.ToString();
            }
            return this.encoded;
        }

    }

}