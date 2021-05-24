using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;

namespace ShiftEverywhere.DiME
{
    public class IdentityIssuingRequest
    {
        /* PUBLIC */
        public int Profile {get; private set; }
        public long IssuedAt { get { return this.json.iat;} }
        public string IdentityKey { get { return this.json.iky; } }

        public static IdentityIssuingRequest GenerateRequest(Keypair keypair, Identity.Capability[] capabilities = null) 
        {
            if (keypair.Type != KeypairType.Identity) { throw new ArgumentNullException("KeyPair of invalid type."); }
            if (keypair.PrivateKey == null) { throw new ArgumentNullException("Private key must not be null"); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string[] caps;
            if (capabilities != null)
            {
                caps = new string[capabilities.Length];
                for (int index = 0; index < capabilities.Length; index++)
                {
                    caps[index] = Identity.CapabilityToString(capabilities[index]);
                }
            } 
            else
            {
                caps = new string[1] { Identity.CapabilityToString(Identity.Capability.Authorize) };
            }
            IdentityIssuingRequest iir = new IdentityIssuingRequest(new IdentityIssuingRequest.JSONData(now, keypair.PublicKey, caps), keypair.Profile);
            iir.signature = Crypto.GenerateSignature(iir.Profile, iir.Encode(), keypair.PrivateKey);
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
            return Crypto.GenerateHash(this.Profile, this.Encode());
        }

        public void Verify(Identity.Capability[] allowedCapabilities)
        {
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() < this.IssuedAt) { throw new DateExpirationException("An identity issuing request cannot be issued in the future."); }
            foreach(string cap in this.json.cap)
            {
                if (!allowedCapabilities.Any<Identity.Capability>(c => c == Identity.CapabilityFromString(cap)))
                {
                    throw new IdentityCapabilityException("Illegal capability listed in identity issuing request.");
                }
            }
            Crypto.VerifySignature(this.Profile, this.Encode(), this.signature, this.IdentityKey);
        }

        #region -- INTERNAL --
        internal string[] capabilities { get { return this.json.cap; } }
        #endregion

        #region -- PRIVATE --
        private const string HEADER = "i";
        private string encoded;
        private string signature;
        private struct JSONData
        {
            public long iat { get; set; }
            public string iky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }

            public JSONData(long iat, string iky, string[] cap = null)
            {
                this.iat = iat;
                this.iky = iky;
                this.cap = cap;
            }
        }
        private IdentityIssuingRequest.JSONData json;

        private IdentityIssuingRequest(IdentityIssuingRequest.JSONData parameters, int profile = Crypto.DEFUALT_PROFILE) 
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            this.json = parameters;
            this.Profile = profile;
        }

        private string Encode()
        {
            if ( this.encoded == null ) 
            { 
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                        IdentityIssuingRequest.HEADER,
                                        this.Profile, 
                                        Utility.ToBase64(JsonSerializer.Serialize(this.json)));
                this.encoded = builder.ToString();
            }
            return this.encoded;
        }

        #endregion

    }

}