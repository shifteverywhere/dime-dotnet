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
        public long IssuedAt { get { return this._data.iat;} }
        public string IdentityKey { get { return this._data.iky; } }

        public static IdentityIssuingRequest Generate(Keypair keypair, Identity.Capability[] capabilities = null) 
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
            IdentityIssuingRequest iir = new IdentityIssuingRequest(new IdentityIssuingRequest.InternalData(now, keypair.PublicKey, caps), keypair.Profile);
            iir._signature = Crypto.GenerateSignature(iir.Profile, iir.Encode(), keypair.PrivateKey);
            return iir;
        }

        public static IdentityIssuingRequest Import(string encoded) 
        {
            if (!encoded.StartsWith(IdentityIssuingRequest._HEADER)) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { '.' });
            if (components.Length != 3 ) { throw new ArgumentException("Unexpected number of components found then decoding identity issuing request."); }
            int profile = int.Parse(components[0].Substring(1));
            byte[] json = Utility.FromBase64(components[1]);
            IdentityIssuingRequest.InternalData parameters = JsonSerializer.Deserialize<IdentityIssuingRequest.InternalData>(json);
            IdentityIssuingRequest iir = new IdentityIssuingRequest(parameters, profile);
            iir._signature = components[2];
            iir._encoded = encoded.Substring(0, encoded.LastIndexOf('.'));
            //iir.isImmutable = true;
            return iir;
        }

        public string Export() 
        {
             return this.Encode() + "." + this._signature;
        }

        /// <summary>Helper function to quickly check if a string is potentially a DiME encoded identity issuing request object.</summary>
        /// <param name="encoded">The string to validate.</param>
        /// <returns>An indication if the string is a DiME encoded identity issuing request.</returns>
        public static bool IsIdentityIssuingRequest(string encoded)
        {
            return encoded.StartsWith(IdentityIssuingRequest._HEADER);
        }

        public string Thumbprint() 
        {
            return Crypto.GenerateHash(this.Profile, this.Encode());
        }

        public void Verify(Identity.Capability[] allowedCapabilities)
        {
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() < this.IssuedAt) { throw new DateExpirationException("An identity issuing request cannot be issued in the future."); }
            foreach(string cap in this._data.cap)
            {
                if (!allowedCapabilities.Any<Identity.Capability>(c => c == Identity.CapabilityFromString(cap)))
                {
                    throw new IdentityCapabilityException("Illegal capability listed in identity issuing request.");
                }
            }
            Crypto.VerifySignature(this.Profile, this.Encode(), this._signature, this.IdentityKey);
        }

        #region -- INTERNAL --
        internal string[] capabilities { get { return this._data.cap; } }
        #endregion

        #region -- PRIVATE --
        private const string _HEADER = "i";
        private string _encoded;
        private string _signature;
        private struct InternalData
        {
            public long iat { get; set; }
            public string iky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }

            public InternalData(long iat, string iky, string[] cap = null)
            {
                this.iat = iat;
                this.iky = iky;
                this.cap = cap;
            }
        }
        private IdentityIssuingRequest.InternalData _data;

        private IdentityIssuingRequest(IdentityIssuingRequest.InternalData parameters, int profile = Crypto.DEFUALT_PROFILE) 
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            this._data = parameters;
            this.Profile = profile;
        }

        private string Encode()
        {
            if ( this._encoded == null ) 
            { 
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                        IdentityIssuingRequest._HEADER,
                                        this.Profile, 
                                        Utility.ToBase64(JsonSerializer.Serialize(this._data)));
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

    }

}