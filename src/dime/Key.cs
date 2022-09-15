//
//  Key.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
// 
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;

namespace DiME
{
    /// <summary>
    /// Represents cryptographic keys. This may be keys for signing and verifying other Di:ME items and envelopes, used
    /// for encryption purposes, or when exchanging shared keys between entities.
    /// </summary>
    public class Key: Item
    {
        #region -- PUBLIC --

        /// <summary>
        /// A tag identifying the Di:ME item type, part of the header.
        /// </summary>
        public const string _TAG = "KEY";
        /// <summary>
        /// Returns the tag of the Di:ME item.
        /// </summary>
        public override string Tag => _TAG;

        /// <summary>
        /// Returns the version of the Di:ME specification for which this key was generated.
        /// </summary>
        [Obsolete("This method is no longer used.")]
        public int Version => Dime.Version;
         /// <summary>
         /// Returns the type of the key. The type determines what the key may be used for, this since it is also
         /// closely associated with the cryptographic algorithm the key is generated for.
         /// </summary>
         public KeyType Type { 
            get
            {
                var key = Claims().Get<string>(Claim.Key) ?? Claims().Get<string>(Claim.Pub);
                return GetAlgorithmFamily(Base58.Decode(key)) switch
                {
                    AlgorithmFamily.Aead => KeyType.Encryption,
                    AlgorithmFamily.Ecdh => KeyType.Exchange,
                    AlgorithmFamily.Eddsa => KeyType.Identity,
                    AlgorithmFamily.Hash => KeyType.Authentication,
                    _ => KeyType.Undefined
                };
            }
        }
         
        /// <summary>
        /// The secret part of the key. This part should never be stored or transmitted in plain text.
        /// </summary>
        public string Secret => Claims().Get<string>(Claim.Key);
        /// <summary>
        /// The public part of the key. This part may be stored or transmitted in plain text.
        /// </summary>
        public string Public => Claims().Get<string>(Claim.Pub);
        
        /// <summary>
        /// Empty constructor, not to be used. Required for Generics.
        /// </summary>
        public Key() { }

        /// <summary>
        /// Will generate a new Key with a specified type.
        /// </summary>
        /// <param name="type">The type of key to generate.</param>
        /// <param name="context">The context to attach to the message, may be null.</param>
        /// <returns>A newly generated key.</returns>
        public static Key Generate(KeyType type, string context) {
            return Generate(type, -1L, null, context);
        }

        /// <summary>
        /// Will generate a new Key with a specified type.
        /// </summary>
        /// <param name="type">The type of key to generate.</param>
        /// <param name="validFor">The number of seconds that the key should be valid for, from the time of issuing.</param>
        /// <param name="issuerId">The identifier of the issuer (creator) of the key, may be null.</param>
        /// <param name="context">The context to attach to the message, may be null.</param>
        /// <returns>A newly generated key.</returns>
        /// <exception cref="ArgumentException"></exception>
        public static Key Generate(KeyType type, long validFor = -1L, Guid? issuerId = null, string context = null)
        {
            if (context is {Length: > Dime.MaxContextLength}) { throw new ArgumentException("Context must not be longer than " + Dime.MaxContextLength + "."); }
            var key = Crypto.GenerateKey(type);
            var claims = key.Claims();
            if (validFor != -1L)
            {
                var exp = key.IssuedAt?.AddSeconds(validFor);
                claims.Put(Claim.Exp, exp);
            }
            claims.Put(Claim.Iss, issuerId);
            claims.Put(Claim.Ctx, context);
            return key;
        }

        /// <summary>
        /// Will instantiate a Key instance from a base 58 encoded string.
        /// </summary>
        /// <param name="encodedKey">A base 58 encoded key.</param>
        /// <returns>A Key instance.</returns>
        public static Key FromBase58Key(string encodedKey)
        {
            return new Key(encodedKey);
        }

        /// <summary>
        /// Will create a copy of a key with only the public part left. This should be used when transmitting a key to
        /// another entity, when the receiving entity only needs the public part.
        /// </summary>
        /// <returns>A new instance of the key with only the public part.</returns>
        public Key PublicCopy()
        {
            var copyKey = new Key(UniqueId, Type, null, RawPublic);
            var claims = copyKey.Claims();
            claims.Put(Claim.Iat, IssuedAt);
            claims.Put(Claim.Exp, ExpiresAt);
            claims.Put(Claim.Iss, IssuerId);
            claims.Put(Claim.Ctx, Context);
            return copyKey;
        }

        #endregion

        #region -- INTERNAL --

        public byte[] RawSecret
        {
            get
            {
                var key = Claims().Get<string>(Claim.Key);
                if (key is null) return null;
                var raw = Base58.Decode(key);
                return Utility.SubArray(raw, HeaderSize, raw.Length - HeaderSize);
            }
        }

        public byte[] RawPublic
        {
            get
            {
                var pub = Claims().Get<string>(Claim.Pub);
                if (pub is null) return null;
                var raw = Base58.Decode(pub);
                return Utility.SubArray(raw, HeaderSize, raw.Length - HeaderSize);
            }
        }

        internal Key(Guid id, KeyType type, byte[] key, byte[] pub)
        {
            var claims = Claims();
            claims.Put(Claim.Uid, id);
            claims.Put(Claim.Iat, DateTime.UtcNow);
            if (key is not null)
                claims.Put(Claim.Key, Base58.Encode(Utility.Combine(HeaderFrom(type, KeyVariant.Secret), key), null));
            if (pub is not null)
                claims.Put(Claim.Pub, Base58.Encode(Utility.Combine(HeaderFrom(type, KeyVariant.Public), pub), null));
        }

        internal Key(string base58Key)
        {
            if (base58Key is not {Length: > 0}) return;
            var bytes = Base58.Decode(base58Key);
            if (bytes is not {Length: > 0}) return;
            var claims = Claims();
            claims.Put(Claim.Uid, Guid.Empty);
            claims.Put(GetKeyVariant(bytes) == KeyVariant.Secret ? Claim.Key : Claim.Pub, base58Key);
        }

        internal new static Key FromEncoded(string encoded)
        {
            var key = new Key();
            key.Decode(encoded);
            return key;
        }
        
        #endregion

        # region -- PROTECTED --

        protected override void CustomDecoding(List<string> components)
        {
            if (components.Count > MinimumNbrComponents + 1)
                throw new FormatException(
                    $"More components in item than expected, got {components.Count}, expected {MinimumNbrComponents + 1}");
            IsSigned = components.Count > MinimumNbrComponents;
        }

        #endregion

        #region -- PRIVATE --

        private const int HeaderSize = 6;

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