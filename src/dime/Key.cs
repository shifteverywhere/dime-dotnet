//
//  Key.cs
//  Di:ME - Digital Identity Message Envelope
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
        public int Version { 
            get {
                byte[] key = (this._claims.key != null) ? this._claims.key : this._claims.pub;
                return key[0];
            }
        }
         public Guid? IssuerId { get { return this._claims.iss; } }
        /// <summary></summary>
        public override Guid UniqueId { get { return this._claims.uid; } }
        public DateTime IssuedAt { get { return Utility.FromTimestamp(this._claims.iat); } }
        /// <summary></summary>
        public DateTime ExpiresAt { get { return Utility.FromTimestamp(this._claims.exp); } }
        /// <summary></summary>

        public KeyType Type { 
            get 
            {  
                byte[] key = (this._claims.key != null) ? this._claims.key : this._claims.pub;
                switch(Key.GetAlgorithmFamily(key))
                {
                    case AlgorithmFamily.Aead: return KeyType.Encryption;
                    case AlgorithmFamily.Ecdh: return KeyType.Exchange;
                    case AlgorithmFamily.Eddsa: return KeyType.Identity;
                    case AlgorithmFamily.Hash: return KeyType.Authentication;
                    default: return KeyType.Undefined;
                }
            }
        }
        /// <summary></summary>
        public string Secret { get { return this._claims.b58Key; } }
        /// <summary></summary>
        public string Public { get { return this._claims.b58Pub; } }
        /// <summary></summary>
        public string Context { get { return this._claims.ctx; } }

        public Key() { }

        /// <summary></summary>
        public static Key Generate(KeyType type, String context) {
            return Key.Generate(type, -1, null, context);
        }

        /// <summary></summary>
        public static Key Generate(KeyType type, double validFor = -1, Guid? issuerId = null, String context = null)
        {
            if (context != null && context.Length > Envelope.MAX_CONTEXT_LENGTH) { throw new ArgumentException("Context must not be longer than " + Envelope.MAX_CONTEXT_LENGTH + "."); }
            Key key = Crypto.GenerateKey(type);
            if (validFor != -1)
            {
                DateTime exp = key.IssuedAt.AddSeconds(validFor);
                key._claims.exp = Utility.ToTimestamp(exp);
            }
            key._claims.iss = issuerId;
            key._claims.ctx = context;
            return key;
        }

        public static Key FromBase58Key(string encodedKey)
        {
            return new Key(encodedKey);
        }

        public Key PublicCopy()
        {
            return new Key(this.UniqueId, this.Type, null, this.RawPublic);
        }

        internal new static Key FromEncoded(string encoded)
        {
            Key keybox = new Key();
            keybox.Decode(encoded);
            return keybox;
        }

        #endregion

        #region -- INTERNAL --

        internal byte[] RawSecret { get { return (this._claims.key != null ) ? Utility.SubArray(this._claims.key, Key._HEADER_SIZE, this._claims.key.Length - Key._HEADER_SIZE) : null; } }
        internal byte[] RawPublic { get { return (this._claims.pub != null ) ? Utility.SubArray(this._claims.pub, Key._HEADER_SIZE, this._claims.pub.Length - Key._HEADER_SIZE) : null; } }

        internal Key(Guid id, KeyType type, byte[] key, byte[] pub)
        {
            DateTime iat = DateTime.UtcNow;
            this._claims = new KeyClaims(null, 
                                         id, 
                                         Utility.ToTimestamp(iat),
                                         null,
                                         (key != null) ? Utility.Combine(Key.headerFrom(type, KeyVariant.Secret), key) : null,
                                         (pub != null) ? Utility.Combine(Key.headerFrom(type, KeyVariant.Public), pub) : null,
                                         null);
        }

        internal Key(string base58key)
        {
            if (base58key != null && base58key.Length > 0) {
                byte[] bytes = Base58.Decode(base58key);
                if (bytes != null && bytes.Length > 0) {
                    switch (Key.GetKeyVariant(bytes)) {
                        case KeyVariant.Secret: 
                            this._claims = new KeyClaims(null, Guid.Empty, null, null, bytes, null, null); 
                            break;
                        case KeyVariant.Public: 
                            this._claims = new KeyClaims(null, Guid.Empty, null, null, null, bytes, null);
                            break;
                        default:
                            throw new FormatException("Invalid key. (K1010)");
                    }
                }
            }
            
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

        private static readonly int _NBR_EXPECTED_COMPONENTS = 2;
        private static readonly int _TAG_INDEX = 0;
        private static readonly int _CLAIMS_INDEX = 1;
        private static readonly int _HEADER_SIZE = 6;
        private KeyClaims _claims;

        private struct KeyClaims
        {
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public Guid? iss { get; set; }
            public Guid uid { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string iat { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string exp { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
            public byte[] key { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
            public byte[] pub { get; set; }

            [JsonPropertyName("key")][JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string b58Key { get { return (this.key != null) ? Base58.Encode(this.key, null) : null; } }

            [JsonPropertyName("pub")][JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string b58Pub { get { return (this.pub != null) ? Base58.Encode(this.pub, null) : null; } }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string ctx { get; set; }

            public KeyClaims(Guid? iss, Guid uid, string iat, string exp, byte[] key, byte[] pub, string ctx)
            {
                this.iss = iss;
                this.uid = uid;
                this.iat = iat;
                this.exp = exp;
                this.key = key;
                this.pub = pub;
                this.ctx = ctx;
            }

            [JsonConstructor]
            public KeyClaims(Guid? iss, Guid uid, string iat, string exp, string b58Key, string b58Pub, string ctx) {
                this.iss = iss;
                this.uid = uid;
                this.iat = iat;
                this.exp = exp;
                this.key = (b58Key != null) ? Base58.Decode(b58Key) : null;
                this.pub = (b58Pub != null) ? Base58.Decode(b58Pub) : null;
                this.ctx = ctx;
            }
        }

        private static byte[] headerFrom(KeyType type, KeyVariant variant) {
            AlgorithmFamily algorithmFamily = Key.GetAlgorithmFamilyFromType(type);
            byte[] header = new byte[Key._HEADER_SIZE];
            header[0] = (byte)Envelope.DIME_VERSION;
            header[1] = (byte)algorithmFamily;
            switch (algorithmFamily) {
                case AlgorithmFamily.Aead:
                    header[2] = (byte) 0x01; // 0x01 == XChaCha20-Poly1305
                    header[3] = (byte) 0x02; // 0x02 == 256-bit key size
                    break;
                case AlgorithmFamily.Ecdh:
                    header[2] = (byte) 0x02; // 0x02 == X25519
                    header[3] = (byte)variant;
                    break;
                case AlgorithmFamily.Eddsa:
                    header[2] = (byte) 0x01; // 0x01 == Ed25519
                    header[3] = (byte)variant;
                    break;
                case AlgorithmFamily.Hash:
                    header[2] = (byte) 0x01; // 0x01 == Blake2b
                    header[3] = (byte) 0x02; // 0x02 == 256-bit key size
                    break;
            }
            return header;
        }    

        private static AlgorithmFamily GetAlgorithmFamilyFromType(KeyType type) {
            switch(type)
            {
                case KeyType.Encryption: return AlgorithmFamily.Aead;
                case KeyType.Exchange: return AlgorithmFamily.Ecdh;
                case KeyType.Identity: return AlgorithmFamily.Eddsa;
                case KeyType.Authentication: return AlgorithmFamily.Hash;
                default: throw new InvalidOperationException($"Unexpected value: {type}");
            }
        }

        private static AlgorithmFamily GetAlgorithmFamily(byte[] key) {
            return (AlgorithmFamily)Enum.ToObject(typeof(AlgorithmFamily), key[1]);
        }

        private static KeyVariant GetKeyVariant(byte[] key) {
            AlgorithmFamily family = Key.GetAlgorithmFamily(key);
            if (family == AlgorithmFamily.Ecdh || family == AlgorithmFamily.Eddsa) {
                return (KeyVariant)Enum.ToObject(typeof(KeyVariant), key[3]);
            }
            return KeyVariant.Secret;
        }

        #endregion
    }

}