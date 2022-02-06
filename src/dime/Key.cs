//
//  Key.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public class Key: Item
    {
        #region -- PUBLIC --

        public const string _TAG = "KEY";
        public override string Tag => _TAG;

        public int Version { 
            get {
                var key = _claims.key ?? _claims.pub;
                return key[0];
            }
        }
         public Guid? IssuerId => _claims.iss;
         /// <summary></summary>
        public override Guid UniqueId => _claims.uid;
         public DateTime IssuedAt => Utility.FromTimestamp(_claims.iat);
         /// <summary></summary>
        public DateTime ExpiresAt => Utility.FromTimestamp(_claims.exp);
         /// <summary></summary>
         public KeyType Type { 
            get
            {
                var key = _claims.key ?? _claims.pub;
                return GetAlgorithmFamily(key) switch
                {
                    AlgorithmFamily.Aead => KeyType.Encryption,
                    AlgorithmFamily.Ecdh => KeyType.Exchange,
                    AlgorithmFamily.Eddsa => KeyType.Identity,
                    AlgorithmFamily.Hash => KeyType.Authentication,
                    _ => KeyType.Undefined
                };
            }
        }
        /// <summary></summary>
        public string Secret => _claims.B58Key;
        /// <summary></summary>
        public string Public => _claims.B58Pub;
        /// <summary></summary>
        public string Context => _claims.ctx;

        public Key() { }

        /// <summary></summary>
        public static Key Generate(KeyType type, string context) {
            return Generate(type, -1L, null, context);
        }

        /// <summary></summary>
        public static Key Generate(KeyType type, long validFor = -1L, Guid? issuerId = null, string context = null)
        {
            if (context is {Length: > Envelope._MAX_CONTEXT_LENGTH}) { throw new ArgumentException("Context must not be longer than " + Envelope._MAX_CONTEXT_LENGTH + "."); }
            var key = Crypto.GenerateKey(type);
            if (validFor != -1L)
            {
                var exp = key.IssuedAt.AddSeconds(validFor);
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
            return new Key(UniqueId, Type, null, RawPublic);
        }

        internal new static Key FromEncoded(string encoded)
        {
            var key = new Key();
            key.Decode(encoded);
            return key;
        }

        #endregion

        #region -- INTERNAL --

        internal byte[] RawSecret => (_claims.key != null ) ? Utility.SubArray(_claims.key, HeaderSize, _claims.key.Length - HeaderSize) : null;
        internal byte[] RawPublic => (_claims.pub != null ) ? Utility.SubArray(_claims.pub, HeaderSize, _claims.pub.Length - HeaderSize) : null;

        internal Key(Guid id, KeyType type, byte[] key, byte[] pub)
        {
            DateTime iat = DateTime.UtcNow;
            _claims = new KeyClaims(null, 
                id, 
                Utility.ToTimestamp(iat),
                null,
                (key != null) ? Utility.Combine(HeaderFrom(type, KeyVariant.Secret), key) : null,
                (pub != null) ? Utility.Combine(HeaderFrom(type, KeyVariant.Public), pub) : null,
                null);
        }

        internal Key(string base58Key)
        {
            if (base58Key is not {Length: > 0}) return;
            var bytes = Base58.Decode(base58Key);
            if (bytes is {Length: > 0})
            {
                _claims = GetKeyVariant(bytes) switch
                {
                    KeyVariant.Secret => new KeyClaims(null, Guid.Empty, null, null, bytes, null, null),
                    KeyVariant.Public => new KeyClaims(null, Guid.Empty, null, null, null, bytes, null),
                    _ => throw new FormatException("Invalid key. (K1010)")
                };
            }

        }

        #endregion

        # region -- PROTECTED --

        protected override void Decode(string encoded)
        {
            var components = encoded.Split(new[] { Envelope._COMPONENT_DELIMITER });
            if (components.Length != NbrExpectedComponents) { throw new FormatException($"Unexpected number of components for identity issuing request, expected {NbrExpectedComponents}, got {components.Length}."); }
            if (components[TagIndex] != _TAG) { throw new FormatException($"Unexpected item tag, expected: \"{_TAG}\", got \"{components[TagIndex]}\"."); }
            var json = Utility.FromBase64(components[ClaimsIndex]);
            _claims = JsonSerializer.Deserialize<KeyClaims>(json);
            Encoded = encoded;
        }

        protected override string Encode()
        {
            if (Encoded != null) return Encoded;
            var builder = new StringBuilder();
            builder.Append(_TAG);
            builder.Append(Envelope._COMPONENT_DELIMITER);
            builder.Append(Utility.ToBase64(JsonSerializer.Serialize(_claims)));
            Encoded = builder.ToString();
            return Encoded;
        }

        #endregion

        #region -- PRIVATE --

        private const int NbrExpectedComponents = 2;
        private const int TagIndex = 0;
        private const int ClaimsIndex = 1;
        private const int HeaderSize = 6;
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
            public string B58Key => (key != null) ? Base58.Encode(key, null) : null;

            [JsonPropertyName("pub")][JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string B58Pub => pub != null ? Base58.Encode(pub, null) : null;

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
                this.key = b58Key != null ? Base58.Decode(b58Key) : null;
                this.pub = b58Pub != null ? Base58.Decode(b58Pub) : null;
                this.ctx = ctx;
            }
        }

        private static byte[] HeaderFrom(KeyType type, KeyVariant variant) {
            var algorithmFamily = GetAlgorithmFamilyFromType(type);
            var header = new byte[HeaderSize];
            header[0] = Envelope._DIME_VERSION;
            header[1] = (byte)algorithmFamily;
            switch (algorithmFamily) {
                case AlgorithmFamily.Aead:
                    header[2] = 0x01; // 0x01 == XChaCha20-Poly1305
                    header[3] = 0x02; // 0x02 == 256-bit key size
                    break;
                case AlgorithmFamily.Ecdh:
                    header[2] = 0x02; // 0x02 == X25519
                    header[3] = (byte)variant;
                    break;
                case AlgorithmFamily.Eddsa:
                    header[2] = 0x01; // 0x01 == Ed25519
                    header[3] = (byte)variant;
                    break;
                case AlgorithmFamily.Hash:
                    header[2] = 0x01; // 0x01 == Blake2b
                    header[3] = 0x02; // 0x02 == 256-bit key size
                    break;
                case AlgorithmFamily.Undefined:
                default:
                    throw new ArgumentOutOfRangeException($"The algorithm familty of key type {type} is not supported or invalid.");
            }
            return header;
        }    

        private static AlgorithmFamily GetAlgorithmFamilyFromType(KeyType type)
        {
            return type switch
            {
                KeyType.Encryption => AlgorithmFamily.Aead,
                KeyType.Exchange => AlgorithmFamily.Ecdh,
                KeyType.Identity => AlgorithmFamily.Eddsa,
                KeyType.Authentication => AlgorithmFamily.Hash,
                _ => throw new InvalidOperationException($"Unexpected value: {type}")
            };
        }

        private static AlgorithmFamily GetAlgorithmFamily(IReadOnlyList<byte> key) {
            return (AlgorithmFamily)Enum.ToObject(typeof(AlgorithmFamily), key[1]);
        }

        private static KeyVariant GetKeyVariant(byte[] key) {
            var family = GetAlgorithmFamily(key);
            if (family is AlgorithmFamily.Ecdh or AlgorithmFamily.Eddsa) {
                return (KeyVariant)Enum.ToObject(typeof(KeyVariant), key[3]);
            }
            return KeyVariant.Secret;
        }

        #endregion
    }

}