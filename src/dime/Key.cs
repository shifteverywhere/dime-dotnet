//
//  Key.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
// 
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Diagnostics;
using System.Linq;

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
        public const string ItemIdentifier = "KEY";
        /// <summary>
        /// Returns the tag of the Di:ME item.
        /// </summary>
        public override string Identifier => ItemIdentifier;

        /// <summary>
        /// Returns the version of the Di:ME specification for which this key was generated.
        /// </summary>
        [Obsolete("This method is no longer used, use Dime.Version instead.")]
        public int Version => Dime.Version;
         /// <summary>
         /// Returns the type of the key. The type determines what the key may be used for, this since it is also
         /// closely associated with the cryptographic algorithm the key is generated for.
         /// </summary>
         [Obsolete("This method is no longer used, use Key.Use instead.")]
         public KeyType Type { 
            get
            {
                if (_type is not null) return (KeyType) _type;
                if (IsLegacy)
                {
                    var key = Claims().Get<string>(Claim.Key);
                    if (key is null)
                    {
                        key = Claims().Get<string>(Claim.Pub);
                        DecodeKey(key, Claim.Pub);
                    }
                    else
                        DecodeKey(key, Claim.Key);
                }
                else
                {
                    if (HasUse(KeyUse.Sign))
                        _type = KeyType.Identity;
                    else if (HasUse(KeyUse.Exchange))
                        _type = KeyType.Exchange;
                    else if (HasUse(KeyUse.Encrypt))
                        _type = KeyType.Encryption;
                }
                Debug.Assert(_type != null, "Unexpected error, unable to get legacy type of key.");
                return (KeyType) _type;
            }
        }

         /// <summary>
         /// The cryptographic suite used to generate they key.
         /// </summary>
         public string CryptoSuiteName
         {
             get
             {
                 if (_suiteName is null)
                 {
                     if (KeyBytes(Claim.Key) is null)
                     {
                         KeyBytes(Claim.Pub);
                     }
                 }
                 return _suiteName;
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
        /// Returns the raw byte array of the requested key. Valid claims to request are Claim.KEY and Claim.PUB.
        /// </summary>
        /// <param name="claim">The key, expressed as a claim, to request bytes of.</param>
        /// <returns> The raw byte array of the key, null if none exists.</returns>
        /// <exception cref="ArgumentException"></exception>
        public byte[] KeyBytes(Claim claim)
        {
            if (claim == Claim.Key)
            {
                if (_secretBytes == null)
                    DecodeKey(Claims().Get<string>(Claim.Key), Claim.Key);
                return _secretBytes;
            } 
            if (claim == Claim.Pub)
            {
                if (_publicBytes == null)
                    DecodeKey(Claims().Get<string>(Claim.Pub), Claim.Pub);
                return _publicBytes;
            }
            throw new ArgumentException($"Invalid claim for key provided: {claim}.");
        }

        /// <summary>
        /// A list of cryptographic uses that the key may perform.
        /// </summary>
        public ReadOnlyCollection<KeyUse> Use
        {
            get
            {
                if (_use is not null) return _use;
                var usage = Claims().Get<List<string>>(Claim.Use);
                if (usage is not null)
                {
                    _use = usage.ConvertAll(input =>
                    {
                        Enum.TryParse(input, true, out KeyUse use);
                        return use;
                    }).AsReadOnly();
                }
                else
                {
                    // This may be legacy
                    KeyBytes(Claim.Pub);
                    KeyBytes(Claim.Key);
                    _use = new ReadOnlyCollection<KeyUse>(new List<KeyUse>(){ Key.KeyUseFromKeyType(Type) });
                }
                return _use;
            }
        }

        /// <summary>
        /// Indicates if a key may be used for a specific cryptographic use.
        /// </summary>
        /// <param name="use">The use to test for.</param>
        /// <returns>True if key supports the use, false otherwise.</returns>
        public bool HasUse(KeyUse use)
        {
            return Use.Contains(use);
        }
        
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
        [Obsolete("Obsolete method, use Generate(List<KeyUse>, string) instead.")]
        public static Key Generate(KeyType type, string context) {
            return Generate(new List<KeyUse>() { KeyUseFromKeyType(type) }, Dime.NoExpiration, null, context);
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
        [Obsolete("Obsolete method, use Generate(List<KeyUse>, long, Guid?, string, string) instead.")]
        public static Key Generate(KeyType type, long validFor = Dime.NoExpiration, Guid? issuerId = null, string context = null)
        {
            return Generate(new List<KeyUse>() { KeyUseFromKeyType(type) }, validFor, issuerId, context);
        }

        /// <summary>
        /// Will generate a new Key for a specific cryptographic usage and attach a specified context.
        /// </summary>
        /// <param name="use">The use of the key.</param>
        /// <param name="context">The context to attach to the key, may be null.</param>
        /// <returns>A newly generated key.</returns>
        public static Key Generate(List<KeyUse> use, string context = null)
        {
            return Key.Generate(use, Dime.NoExpiration, null, context);
        }

        /// <summary>
        /// Will generate a new Key for a specific cryptographic usage, an expiration date, and the identifier of the
        /// issuer. Abiding to the expiration date is application specific as the key will continue to function after
        /// the expiration date. Providing -1 as validFor will skip setting an expiration date. The specified context
        /// will be attached to the generated key. The cryptographic suite specified will be used when generating the
        /// key.
        /// </summary>
        /// <param name="use">The use of the key.</param>
        /// <param name="validFor">The number of seconds that the key should be valid for, from the time of issuing.</param>
        /// <param name="issuerId">The identifier of the issuer (creator) of the key, may be null.</param>
        /// <param name="context">The context to attach to the key, may be null.</param>
        /// <param name="suiteName">The name of the cryptographic suite to use, if null, then the default suite will be used.</param>
        /// <returns>A newly generated key.</returns>
        /// <exception cref="ArgumentException"></exception>
        public static Key Generate(List<KeyUse> use, long validFor = Dime.NoExpiration, Guid? issuerId = null, string context = null, string suiteName = null)
        {
            if (context is {Length: > Dime.MaxContextLength}) { throw new ArgumentException("Context must not be longer than " + Dime.MaxContextLength + "."); }
            var keyBytes = Dime.Crypto.GenerateKey(use, suiteName ?? Dime.Crypto.DefaultSuiteName);
            var key = new Key(Guid.NewGuid(), 
                use, 
                keyBytes[(int)KeyIndex.SecretKey], 
                keyBytes.Length == 2 ? keyBytes[(int)KeyIndex.PublicKey] : null,
                suiteName);
            var claims = key.Claims();
            if (validFor != -1L)
                claims.Put(Claim.Exp, claims.GetDateTime(Claim.Iat)?.AddSeconds(validFor));
            claims.Put(Claim.Iss, issuerId);
            claims.Put(Claim.Ctx, context);
            return key;
        }

        /// <summary>
        /// Will create a copy of a key with only the public part left. This should be used when transmitting a key to
        /// another entity, when the receiving entity only needs the public part.
        /// </summary>
        /// <returns>A new instance of the key with only the public part.</returns>
        public Key PublicCopy()
        {
            var copyKey = new Key(Use.ToList(), null, Public, _suiteName);
            var claims = copyKey.Claims();
            claims.Put(Claim.Uid, UniqueId);
            claims.Put(Claim.Iat, IssuedAt);
            claims.Put(Claim.Exp, ExpiresAt);
            claims.Put(Claim.Iss, IssuerId);
            claims.Put(Claim.Ctx, Context);
            return copyKey;
        }

        /// <summary>
        /// Generates a shared secret from the current key and another provided key. Both keys must have key usage
        /// 'Exchange' specified.
        /// </summary>
        /// <param name="key">The other key to use with the key exchange (generation of shared key).</param>
        /// <param name="use">The requested usage of the generated shared key, usually 'Encrypt'.</param>
        /// <returns>The generated shared key.</returns>
        public Key GenerateSharedSecret(Key key, List<KeyUse> use)
        {
            var sharedKey = Dime.Crypto.GenerateSharedSecret(this, key, use);
            return new Key(Guid.NewGuid(), use, sharedKey, null, _suiteName);
        }
        
        #endregion

        #region -- INTERNAL --

        internal Key(Guid id, List<KeyUse> use, byte[] key, byte[] pub, string suiteName)
        {
            _suiteName = suiteName ?? Dime.Crypto.DefaultSuiteName;
            var claims = Claims();
            claims.Put(Claim.Use, use.ConvertAll(keyUse => keyUse.ToString().ToLower()));
            claims.Put(Claim.Uid, id);
            claims.Put(Claim.Iat, DateTime.UtcNow);
            if (key is not null)
                claims.Put(Claim.Key, EncodedKey(_suiteName, key));
            if (pub is not null)
                claims.Put(Claim.Pub, EncodedKey(_suiteName, pub));
        }

        internal Key(List<KeyUse> use, string key, string pub, string suiteName)
        {
            _suiteName = suiteName ?? Dime.Crypto.DefaultSuiteName;
            var claims = Claims();
            claims.Put(Claim.Use, use.ConvertAll(keyUse => keyUse.ToString().ToLower()));
            if (key is not null)
                claims.Put(Claim.Key, key);
            if (pub is not null)
                claims.Put(Claim.Pub, pub);
        }

        internal Key(List<KeyUse> use, string key, Claim claim)
        {
            Claims().Put(Claim.Use, use.ConvertAll(keyUse => keyUse.ToString().ToLower()));
            Claims().Put(claim, key);
        }

        internal static void ConvertKeyToLegacy(Item item, KeyUse use, Claim claim)
        {
            var key = item.Claims().Get<string>(claim);
            if (key is null) { return; }
            var header = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00 };
            var b58 = key[(key.IndexOf(Dime.ComponentDelimiter) + 1)..];
            var rawKey = Base58.Decode(b58);
            var legacyKey = Utility.Combine(header, rawKey);
            legacyKey[1] = use == KeyUse.Encrypt ? (byte) 0x10 : use == KeyUse.Exchange ? (byte) 0x40 : (byte) 0x80;
            legacyKey[2] = use == KeyUse.Exchange ? (byte) 0x02 : (byte) 0x01;
            if (claim == Claim.Pub)
                legacyKey[3] = 0x01;
            else if (use == KeyUse.Encrypt)
                legacyKey[3] = 0x02;
            item.Claims().Put(claim, Base58.Encode(legacyKey, null));
        }
        
        #endregion

        # region -- PROTECTED --

        /// <summary>
        /// Any additional decoding done by subclasses of Item.
        /// </summary>
        /// <param name="components">Components to decode.</param>
        /// <exception cref="FormatException"></exception>
        protected override void CustomDecoding(List<string> components)
        {
            if (components.Count > MinimumNbrComponents + 1)
                throw new FormatException($"More components in item than expected, got {components.Count}, expected {MinimumNbrComponents + 1}");
            IsSigned = components.Count > MinimumNbrComponents;
        }

        #endregion

        #region -- PRIVATE --

        private const int CryptoSuiteIndex = 0;
        private const int EncodedKeyIndex = 1;
        private const int LegacyKeyHeaderSize = 6;
        private string _suiteName;
        private ReadOnlyCollection<KeyUse> _use;
        private byte[] _secretBytes;
        private byte[] _publicBytes;
        private KeyType? _type;
 
        [Obsolete("Obsolete method, remove once legacy is not supported anymore.")]
        private static KeyType GetKeyType(IReadOnlyList<byte> key)
        {
            switch ((AlgorithmFamily)Enum.ToObject(typeof(AlgorithmFamily), key[1]))
            {
                case AlgorithmFamily.Aead:
                    return KeyType.Encryption;
                case AlgorithmFamily.Ecdh:
                    return KeyType.Exchange;
                case AlgorithmFamily.Eddsa:
                    return KeyType.Identity;
                case AlgorithmFamily.Hash:
                    return KeyType.Authentication;
                case AlgorithmFamily.Undefined:
                default:
                    return KeyType.Undefined;
            }
        }
        
        private static string EncodedKey(string suiteName, byte[] rawKey)
        {
            return $"{suiteName}{Dime.ComponentDelimiter}{Base58.Encode(rawKey, null)}";
        }
        
        private void DecodeKey(string encoded, Claim claim)
        {
            if (encoded is null || encoded.Length == 0) { return; }
            var components = encoded.Split(new[] { Dime.ComponentDelimiter });
            string suiteName;
            var legacyKey = false;
            if (components.Length == 2)
                suiteName = components[CryptoSuiteIndex].ToUpper();
            else
            {
                // This will be treated as legacy
                suiteName = Dime.Crypto.DefaultSuiteName;
                legacyKey = true;
            }
            if (_suiteName is null)
                _suiteName = suiteName;
            else if (!_suiteName.Equals(suiteName))
                throw new InvalidOperationException($"Unable to decode key, public and secret keys generated using different cryptographic suites: {_suiteName} and {suiteName}.");
            byte[] rawKey;
            if (!legacyKey)
                rawKey = Base58.Decode(components[EncodedKeyIndex]);
            else
            {
                var decoded = Base58.Decode(encoded);
                rawKey = Utility.SubArray(decoded, LegacyKeyHeaderSize);
                _type = GetKeyType(decoded);
            }
            switch (claim)
            {
                case Claim.Key:
                    _secretBytes = rawKey;
                    break;
                case Claim.Pub:
                    _publicBytes = rawKey;
                    break;
                default:
                    throw new ArgumentException($"Unable to decode key, invalid claim provided for key: {claim}.");
            }
            IsLegacy = legacyKey;
        }
        
        private static KeyUse KeyUseFromKeyType(KeyType type)
        {
            switch (type)
            {
                case KeyType.Identity:
                    return KeyUse.Sign;
                case KeyType.Exchange:
                    return KeyUse.Exchange;
                case KeyType.Encryption:
                    return KeyUse.Encrypt;
                case KeyType.Undefined:
                case KeyType.Authentication:
                default:
                    throw new ArgumentOutOfRangeException(nameof(type), type, null);
            }
        }
        
        #endregion
    }

}