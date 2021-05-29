using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;
using System.Collections.Generic;

namespace ShiftEverywhere.DiME
{
    public class IdentityIssuingRequest
    {
        /* PUBLIC */
        /// <summary></summary>
        public int Profile {get; private set; }
        /// <summary></summary>
        public long IssuedAt { get { return this._data.iat;} }
        /// <summary></summary>
        public string IdentityKey { get { return this._data.iky; } }
        /// <summary>The capabilities requested in this identity issuing request.</summary>
        public List<Capability> Capabilities 
        { 
            get 
            { 
                if (this._capabilities == null)
                {
                    this._capabilities = new List<string>(this._data.cap).ConvertAll(str => { Capability cap; Enum.TryParse<Capability>(str, true, out cap); return cap; });
                }
                return this._capabilities;
            } 
        }

        public static IdentityIssuingRequest Generate(Keypair keypair, List<Capability> capabilities = null) 
        {
            if (keypair.Type != KeypairType.Identity) { throw new ArgumentNullException(nameof(keypair), "KeyPair of invalid type."); }
            if (keypair.PrivateKey == null) { throw new ArgumentNullException(nameof(keypair), "Private key must not be null"); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string[] cap;
            if (capabilities != null && capabilities.Count > 0)
            {
                cap = capabilities.ConvertAll(c => c.ToString().ToLower()).ToArray();
            }
            else
            {
                cap = new string[1] { Capability.Generic.ToString().ToLower() };
            }
            IdentityIssuingRequest iir = new IdentityIssuingRequest(new IdentityIssuingRequest.InternalData(now, keypair.PublicKey, cap), keypair.Profile);
            iir._signature = Crypto.GenerateSignature(iir.Profile, iir.Encode(), keypair.PrivateKey);
            return iir;
        }

        public static IdentityIssuingRequest Import(string encoded) 
        {
            if (!encoded.StartsWith(IdentityIssuingRequest._HEADER)) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { IdentityIssuingRequest._MAIN_DELIMITER });
            if (components.Length != 3 ) { throw new ArgumentException("Unexpected number of components found then decoding identity issuing request."); }
            int profile = int.Parse(components[0].Substring(1));
            byte[] json = Utility.FromBase64(components[1]);
            IdentityIssuingRequest.InternalData parameters = JsonSerializer.Deserialize<IdentityIssuingRequest.InternalData>(json);
            IdentityIssuingRequest iir = new IdentityIssuingRequest(parameters, profile);
            iir._signature = components[2];
            iir._encoded = encoded.Substring(0, encoded.LastIndexOf(IdentityIssuingRequest._MAIN_DELIMITER));
            return iir;
        }

        public string Export() 
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(Encode());
            sb.Append(IdentityIssuingRequest._MAIN_DELIMITER);
            sb.Append(this._signature);
            return sb.ToString();
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

        public void Verify()
        {
            if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() < this.IssuedAt) { throw new DateExpirationException("An identity issuing request cannot be issued in the future."); }
            Crypto.VerifySignature(this.Profile, this.Encode(), this._signature, this.IdentityKey);
        }

        public bool HasCapability(Capability capability)
        {
            return this.Capabilities.Any(cap => cap == capability);
        }

        #region -- PRIVATE --
        private const string _HEADER = "i";
        private const char _MAIN_DELIMITER = '.';
        private List<Capability> _capabilities;
        private string _encoded;
        private string _signature;

        private struct InternalData
        {
            public long iat { get; set; }
            public string iky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }

            [JsonConstructor]
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