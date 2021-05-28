using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public enum KeypairType
    {
        Identity = 1,
        Exchange = 2
    }

    public struct Keypair
    {
        #region -- PUBLIC --
        public int Profile { get; private set; }
        public Guid Id { get { return this._data.kid; } }
        public KeypairType Type { get { return this._data.kty; } }
        public string PublicKey { get { return this._data.pub; } }
        public string PrivateKey { get { return this._data.prv; } }

        internal Keypair(Guid id, KeypairType type, string publicKey, string privateKey, int profile)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            if (publicKey == null) { throw new ArgumentNullException(nameof(publicKey), "Provided public key must not be null."); }
            if (privateKey == null) { throw new ArgumentNullException(nameof(privateKey), "Provided public key must not be null."); }
            this._data = new Keypair.InternalData(id, type, publicKey, privateKey);
            this.Profile = profile;
            this._encoded = null;
        }

        public static Keypair Generate(KeypairType type, int profile = Crypto.DEFUALT_PROFILE)
        {
            return Crypto.GenerateKeyPair(profile, type);
        }

        public static Keypair Import(string encoded)
        {
            if (!encoded.StartsWith(Keypair._HEADER)) { throw new DataFormatException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { '.' });
            if (components.Length != 2) { throw new ArgumentException("Unexpected number of components found then decoding keypair."); }
            int profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            byte[] json = Utility.FromBase64(components[1]);
            Keypair.InternalData parameters = JsonSerializer.Deserialize<Keypair.InternalData>(json);
            Keypair keypair = new Keypair(parameters, profile);
            return keypair;
        }

        public string Export() 
        {
            return Encode();
        } 
        #endregion
        #region -- PRIVATE --
        private const string _HEADER = "k";
        private string _encoded;

        private struct InternalData
        {
            public Guid kid { get; set; }
            public KeypairType kty { get; set; }
            public string pub { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string prv { get; set; }

            [JsonConstructor]
            public InternalData(Guid kid, KeypairType kty, string pub, string prv)
            {
                this.kid = kid;
                this.kty = kty;
                this.pub = pub;
                this.prv = prv;
            }
        }
        private InternalData _data;

        private Keypair(InternalData parameters, int profile = Crypto.DEFUALT_PROFILE)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            this._data = parameters;
            this.Profile = profile;
            this._encoded = null;
        }

        private string Encode()
        {
            if ( this._encoded == null ) 
            {  
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}", 
                                    Keypair._HEADER,
                                    this.Profile, 
                                    Utility.ToBase64(JsonSerializer.Serialize(this._data)));
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }
        #endregion
    }

}