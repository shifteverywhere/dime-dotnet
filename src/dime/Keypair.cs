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

    public class Keypair: Dime
    {
        #region -- PUBLIC --

        /// <summary></summary>
        public Guid Id { get { return this._data.kid; } }
        /// <summary></summary>
        public KeypairType Type { get { return this._data.kty; } }
        /// <summary></summary>
        public string PublicKey { get { return this._data.pub; } }
        /// <summary></summary>
        public string PrivateKey { get { return this._data.prv; } }

        /// <summary></summary>
        public Keypair() { }

        /// <summary></summary>
        public static Keypair Generate(KeypairType type, int profile = Crypto.DEFUALT_PROFILE)
        {
            return Crypto.GenerateKeyPair(profile, type);
        }

        /// <summary></summary>
        public override string Export() 
        {
            return Encode();
        }

        /// <summary></summary>
        public override void Verify() { }

        #endregion

        #region -- INTERNAL --

        internal Keypair(Guid id, KeypairType type, string publicKey, string privateKey, int profile)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            if (publicKey == null) { throw new ArgumentNullException(nameof(publicKey), "Provided public key must not be null."); }
            if (privateKey == null) { throw new ArgumentNullException(nameof(privateKey), "Provided public key must not be null."); }
            this._data = new Keypair.KeypairData(id, type, publicKey, privateKey);
            this.Profile = profile;
            this._encoded = null;
        }

        #endregion

        #region -- PROTECTED --

        protected override void Populate(string encoded)
        {
            if (Dime.GetType(encoded) != typeof(Keypair)) { throw new ArgumentException("Invalid header."); }
            string[] components = encoded.Split(new char[] { Dime._MAIN_DELIMITER });
            if (components.Length != 2) { throw new ArgumentException("Unexpected number of components found then decoding keypair."); }
            this.Profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(this.Profile)) { throw new UnsupportedProfileException(); }
            byte[] json = Utility.FromBase64(components[1]);
            this._data = JsonSerializer.Deserialize<Keypair.KeypairData>(json);
        }

        protected override void Verify(string publicKey) { }

        protected override string Encode()
        {
            if ( this._encoded == null ) 
            {  
                StringBuilder builder = new StringBuilder();
                builder.Append('k') ;// The header of an DiME keypair
                builder.Append(this.Profile);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._data)));
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

        #region -- PRIVATE --

        private struct KeypairData
        {
            public Guid kid { get; set; }
            public KeypairType kty { get; set; }
            public string pub { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string prv { get; set; }

            [JsonConstructor]
            public KeypairData(Guid kid, KeypairType kty, string pub, string prv)
            {
                this.kid = kid;
                this.kty = kty;
                this.pub = pub;
                this.prv = prv;
            }
        }
        private Keypair.KeypairData _data;

        #endregion
    }

}