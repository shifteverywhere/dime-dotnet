using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public class KeyBox: Dime
    {
        #region -- PUBLIC --

        /// <summary></summary>
        public Guid Id { get { return this._claims.kid; } }
        /// <summary></summary>
        public KeyType Type { get { return this._claims.kty; } }
        /// <summary></summary>
        public string Key { get { return this._claims.key; } }
        /// <summary></summary>
        public string PublicKey { get { return this._claims.pub; } }

        /// <summary></summary>
        public KeyBox() { }

        /// <summary></summary>
        public static KeyBox GenerateKey(KeyType type, ProfileVersion profile = Crypto.DEFUALT_PROFILE)
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

        internal KeyBox(Guid id, KeyType type, string key, string publicKey, ProfileVersion profile)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }

            if (key == null || key.Length == 0) { throw new ArgumentNullException(nameof(key), "Key must not be empty or null."); }
            if ((type == KeyType.Identity || type == KeyType.Exchange) && (publicKey == null || publicKey.Length == 0)) { throw new ArgumentNullException(nameof(publicKey), "A public key must be provided for asymmetric keys."); }
            this._claims = new KeypairClaims(id, type, key, publicKey);
            this.Profile = profile;
            this._encoded = null;
        }

        #endregion

        #region -- PROTECTED --

        protected override void Populate(string encoded)
        {
            if (Dime.GetType(encoded) != typeof(KeyBox)) { throw new ArgumentException("Invalid header."); }
            string[] components = encoded.Split(new char[] { Dime._MAIN_DELIMITER });
            if (components.Length != 2) { throw new ArgumentException("Unexpected number of components found then decoding keypair."); }
            ProfileVersion profile;
            Enum.TryParse<ProfileVersion>(components[0].Substring(1), true, out profile);
            this.Profile = profile;
            if (!Crypto.SupportedProfile(this.Profile)) { throw new UnsupportedProfileException(); }
            byte[] json = Utility.FromBase64(components[1]);
            this._claims = JsonSerializer.Deserialize<KeypairClaims>(json);
        }

        protected override void Verify(string publicKey) { /* Keypair objects are not yet signed, so just ignore verification. */ }

        protected override string Encode()
        {
            if ( this._encoded == null ) 
            {  
                StringBuilder builder = new StringBuilder();
                builder.Append('k') ;// The header of an DiME keybox
                builder.Append((int)this.Profile);
                builder.Append(Dime._MAIN_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

        #region -- PRIVATE --

        private struct KeypairClaims
        {
            public Guid kid { get; set; }
            public KeyType kty { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string key { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string pub { get; set; }

            [JsonConstructor]
            public KeypairClaims(Guid kid, KeyType kty, string key, string pub)
            {
                this.kid = kid;
                this.kty = kty;
                this.key = key;
                this.pub = pub;
            }
        }
        private KeypairClaims _claims;

        #endregion
    }

}