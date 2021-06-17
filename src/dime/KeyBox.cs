//
//  KeyBox.cs
//  DiME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public class KeyBox: Dime
    {
        #region -- PUBLIC --

        public const string ITID = "aW8uZGltZWZvcm1hdC5reWI"; // base64 of io.dimeformat.kyb
        /// <summary></summary>
        public override Guid Id { get { return this._claims.kid; } }
        /// <summary></summary>
        public KeyType Type { get { return this._claims.kty; } }
        /// <summary></summary>
        public string Key { get { return this._claims.key; } }
        /// <summary></summary>
        public string PublicKey { get { return this._claims.pub; } }

        public KeyBox() { }

        /// <summary></summary>
        public static KeyBox Generate(KeyType type, ProfileVersion profile = Crypto.DEFUALT_PROFILE)
        {
            return Crypto.GenerateKeyPair(profile, type);
        }

        #endregion

        #region -- INTERNAL --

        internal KeyBox(Guid id, KeyType type, string key, string publicKey, ProfileVersion profile)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            if (key == null || key.Length == 0) { throw new ArgumentNullException(nameof(key), "Key must not be empty or null."); }
            if ((type == KeyType.Identity || type == KeyType.Exchange) && (publicKey == null || publicKey.Length == 0)) { throw new ArgumentNullException(nameof(publicKey), "A public key must be provided for asymmetric keys."); }
            this._claims = new KeyBoxClaims((int)profile, id, type, key, publicKey);
            this.Profile = profile;
        }

        internal override void Populate(Identity issuer, string encoded)
        {
            string[] components = encoded.Split(new char[] { Dime._COMPONENT_DELIMITER });
            if (components.Length != KeyBox._NBR_EXPECTED_COMPONENTS) { throw new DataFormatException($"Unexpected number of components for identity issuing request, expected {KeyBox._NBR_EXPECTED_COMPONENTS}, got {components.Length}."); }
            if (components[KeyBox._IDENTIFIER_INDEX] != KeyBox.ITID) { throw new DataFormatException($"Unexpected object identifier, expected: \"{KeyBox.ITID}\", got \"{components[KeyBox._IDENTIFIER_INDEX]}\"."); }
            byte[] json = Utility.FromBase64(components[KeyBox._CLAIMS_INDEX]);
            this._claims = JsonSerializer.Deserialize<KeyBoxClaims>(json);
            this.Profile = (ProfileVersion)this._claims.ver;
        }

        internal string Encoded(bool includeKey, bool includeSignature)
        {
            this._claims.includeKey = (includeKey || this.Type == KeyType.Secret);
            string encoded = Encoded(includeSignature);
            this._claims.includeKey = false;
            return encoded;
        }

        internal override string Encoded(bool includeSignature = false)
        {
            if (this._encoded == null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(KeyBox.ITID);
                builder.Append(Dime._COMPONENT_DELIMITER);
                if (!this._claims.includeKey && this._claims.kty != KeyType.Secret)
                {
                    builder.Append(Utility.ToBase64(JsonSerializer.Serialize(new KeyBoxClaims(this._claims.ver, this._claims.kid, this._claims.kty, null, this._claims.pub))));
                }
                else
                {
                    builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                }
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

        # region -- PROTECTED --
       
        protected override void FixateEncoded(string encoded)
        {
            this._encoded = encoded;
        }

        #endregion

        #region -- PRIVATE --

        private const int _NBR_EXPECTED_COMPONENTS = 2;
        private const int _IDENTIFIER_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;

        private KeyBoxClaims _claims;
        private string _encoded;

        private class KeyBoxClaims
        {
            public int ver { get; set; }
            public Guid kid { get; set; }
            public KeyType kty { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string key { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string pub { get; set; }

            [JsonIgnore]
            public bool includeKey;

            [JsonConstructor]
            public KeyBoxClaims(int ver, Guid kid, KeyType kty, string key, string pub)
            {
                this.ver = ver;
                this.kid = kid;
                this.kty = kty;
                this.key = key;
                this.pub = pub;
                this.includeKey = false;
            }

            public bool ShouldSerializeKey()
            {
                return this.includeKey;
            }
        }
        

        #endregion
    }

}