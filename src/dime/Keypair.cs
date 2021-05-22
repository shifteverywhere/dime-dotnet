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
        [JsonPropertyName("kid")]
        public Guid id { get;}
        [JsonPropertyName("kty")]
        public KeypairType type { get; private set; }
        [JsonPropertyName("pub")]
        public string publicKey { get; private set; }
        [JsonPropertyName("prv")][JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string privateKey { get; private set; }

        public Keypair(Guid id, KeypairType type, string publicKey, string privateKey, int profile = Crypto.DEFUALT_PROFILE)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            if (id == null || publicKey == null || privateKey == null) { throw new ArgumentNullException(); }
            this.id = id;
            this.type = type;
            this.publicKey = publicKey;
            this.privateKey = privateKey;  
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
            Keypair keypair = JsonSerializer.Deserialize<Keypair>(json);
            keypair.profile = profile;
            return keypair;
        }

        public string Export() 
        {
            return Encode();
        } 

        /* PRIVATE */
        private const string HEADER = "k";
        private string encoded;

        public string Encode()
        {
            if ( this.encoded == null ) 
            {  
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                    Keypair.HEADER,
                                    this.profile, 
                                    Utility.ToBase64(JsonSerializer.Serialize(this)));
                this.encoded = builder.ToString();
            }
            return this.encoded;
        }
    }

}