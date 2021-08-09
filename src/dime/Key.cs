//
//  Key.cs
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
    public class Key: Item
    {
        #region -- PUBLIC --

        public const string TAG = "KEY";
        public override string Tag { get { return DiME.Key.TAG; } }
        public Profile Profile { get; private set; }
         public Guid? IssuerId { get { return this._claims.iss; } }
        /// <summary></summary>
        public override Guid UniqueId { get { return this._claims.kid; } }
         public long? IssuedAt { get { return this._claims.iat; } }
        /// <summary></summary>
        public KeyType Type { get; private set; }
        /// <summary></summary>
        public string Secret { get { return this._claims.key; } }
        /// <summary></summary>
        public string Public { get { return this._claims.pub; } }

        public Key() { }

        /// <summary></summary>
        public static Key Generate(KeyType type, Profile profile = Crypto.DEFUALT_PROFILE)
        {
            return Crypto.GenerateKeyBox(profile, type);
        }

        public static Key FromBase58Key(string encodedKey)
        {
            Key keybox = new Key();
            keybox.DecodeKey(encodedKey);
            return keybox;
        }

        public Key PublicCopy()
        {
            return new Key(this.UniqueId, this.Type, null, this.RawPublicKey, this.Profile);
        }

        internal new static Key FromEncoded(string encoded)
        {
            Key keybox = new Key();
            keybox.Decode(encoded);
            return keybox;
        }

        #endregion

        #region -- INTERNAL --

        internal byte[] RawKey { get; private set; }
        internal byte[] RawPublicKey { get; private set; }

        internal Key(Guid id, KeyType type, byte[] key, byte[] publickey, Profile profile = Crypto.DEFUALT_PROFILE)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported profile.", nameof(profile)); }
            long iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            this._claims = new KeyClaims(
                null, 
                id, 
                iat,
                DiME.Key.EncodeKey(key, (byte)type, (byte)KeyVariant.Private, (byte)profile),
                DiME.Key.EncodeKey(publickey, (byte)type, (byte)KeyVariant.Public, (byte)profile));
            this.Type = type;
            this.Profile = profile;
            this.RawKey = key;
            this.RawPublicKey = publickey;
        }

        internal Key(string base58key)
        {
            DecodeKey(base58key);
        }

        #endregion

        # region -- PROTECTED --

        protected override void Decode(string encoded)
        {
            string[] components = encoded.Split(new char[] { Envelope._COMPONENT_DELIMITER });
            if (components.Length != DiME.Key._NBR_EXPECTED_COMPONENTS) { throw new FormatException($"Unexpected number of components for identity issuing request, expected {DiME.Key._NBR_EXPECTED_COMPONENTS}, got {components.Length}."); }
            if (components[DiME.Key._TAG_INDEX] != DiME.Key.TAG) { throw new FormatException($"Unexpected item tag, expected: \"{DiME.Key.TAG}\", got \"{components[DiME.Key._TAG_INDEX]}\"."); }
            byte[] json = Utility.FromBase64(components[DiME.Key._CLAIMS_INDEX]);
            this._claims = JsonSerializer.Deserialize<KeyClaims>(json);
            DecodeKey(this._claims.key);
            DecodeKey(this._claims.pub);
            this._encoded = encoded;
        }

        protected override string Encode()
        {
            if (this._encoded == null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(DiME.Key.TAG);
                builder.Append(Envelope._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

        #region -- PRIVATE --

        private const int _NBR_EXPECTED_COMPONENTS = 2;
        private const int _TAG_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;
        private KeyClaims _claims;

        private struct KeyClaims
        {
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public Guid? iss { get; set; }
            public Guid kid { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public long? iat { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string key { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string pub { get; set; }

            [JsonConstructor]
            public KeyClaims(Guid? iss, Guid kid, long? iat, string key, string pub)
            {
                this.iss = iss;
                this.kid = kid;
                this.iat = iat;
                this.key = key;
                this.pub = pub;
            }

        }
        
        private static string EncodeKey(byte[] key, byte type, byte variant, byte profile)
        {
            if (key == null) return null;
            byte combinedType = (byte)((uint)type | (uint)variant);
            byte[] prefix = { 0x04, profile, combinedType, 0x00 };
            return Base58.Encode(Utility.Combine(prefix, key));
        }

        private void DecodeKey(string encodedKey)
        {
            if (encodedKey != null)
            {
                byte[] bytes = Base58.Decode(encodedKey);
                Profile profile = (Profile)bytes[1];
                if (this.Profile != Profile.Undefined && profile != this.Profile) { throw new FormatException($"Cryptographic profile version mismatch, got: '{profile}', expected: '{this.Profile}'."); }
                this.Profile = profile;
                KeyType type = (KeyType)((byte)((uint)bytes[2] & 0xFE));
                if (this.Type != KeyType.Undefined && type != this.Type) { throw new FormatException($"Key type mismatch, got: '{type}', expected: '{this.Type}'."); }
                this.Type = type;
                KeyVariant variant = (KeyVariant)((byte)((uint)bytes[2] & 0x01));
                switch (variant)
                {
                    case KeyVariant.Public:
                        this.RawPublicKey = Utility.SubArray(bytes, 4);
                        break;
                    case KeyVariant.Private:
                        this.RawKey = Utility.SubArray(bytes, 4);
                        break;
                }
            }
        }

        #endregion
    }

}