using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public enum KeypairType: int
    {
        IdentityKey = 1,
        ExchangeKey = 2
    }

    public struct Keypair
    {
        /* PUBLIC */
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public int profile { get; private set; }
        public Guid id { get { return this.json.kid; } }
        public KeypairType type { get { return this.json.kty; } }
        public string publicKey { get { return this.json.pub; } }
        public string privateKey { get { return this.json.prv; } }

        [JsonConstructor]
        internal Keypair(Guid id, KeypairType type, string publicKey, string privateKey, int profile)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            if (id == null || publicKey == null || privateKey == null) { throw new ArgumentNullException(); }
            this.json = new Keypair.JSONData(id, type, publicKey, privateKey);
            this.profile = profile;
            this.encoded = null;
        }

        public static Keypair GenerateKeypair(KeypairType type, int profile = Crypto.DEFUALT_PROFILE)
        {
            return Crypto.GenerateKeyPair(profile, type);
        }

        public static Keypair Import(string encoded)
        {
            if (!encoded.StartsWith(Keypair.HEADER)) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { '.' });
            if (components.Length != 2) { throw new ArgumentException("Unexpected number of components found then decoding keypair."); }
            int profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            byte[] json = Utility.FromBase64(components[1]);
            Keypair.JSONData parameters = JsonSerializer.Deserialize<Keypair.JSONData>(json);
            Keypair keypair = new Keypair(parameters, profile);
            return keypair;
        }

        public string Export() 
        {
            return Encode();
        } 

        /* PRIVATE */
        private const string HEADER = "k";
        private string encoded;

        private struct JSONData
        {
            public Guid kid { get; set; }
            public KeypairType kty { get; set; }
            public string pub { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string prv { get; set; }

            public JSONData(Guid kid, KeypairType kty, string pub, string prv)
            {
                this.kid = kid;
                this.kty = kty;
                this.pub = pub;
                this.prv = prv;
            }
        }
        private JSONData json;

        private Keypair(JSONData parameters, int profile = Crypto.DEFUALT_PROFILE)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            this.json = parameters;
            this.profile = profile;
            this.encoded = null;
        }

        private string Encode()
        {
            if ( this.encoded == null ) 
            {  
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                    Keypair.HEADER,
                                    this.profile, 
                                    Utility.ToBase64(JsonSerializer.Serialize(this.json)));
                this.encoded = builder.ToString();
            }
            return this.encoded;
        }
    }

}