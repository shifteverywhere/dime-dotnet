//
//  Crypto.cs
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using ASodium;

namespace ShiftEverywhere.DiME
{
    public static class Crypto
    {
        
        public static string GenerateSignature(string data, Key key)
        {
            if (key == null) { throw new ArgumentNullException(nameof(key), "Unable to sign, key must not be null."); }
            if (key.RawSecret == null) { throw new ArgumentNullException(nameof(key), "Unable to sign, key in key must not be null."); }
            if (key.Type != KeyType.Identity) { throw new ArgumentException($"Unable to sign, wrong key type provided, got: {key.Type}, expected: KeyType.Identity."); }
            var signature = SodiumPublicKeyAuth.SignDetached(Encoding.UTF8.GetBytes(data), key.RawSecret);
            return Utility.ToBase64(signature);
        }

        public static void VerifySignature(string data, string signature, Key key)
        {
            if (key == null) { throw new ArgumentNullException(nameof(key), "Unable to verify signature, key must not be null."); }
            if (data == null) { throw new ArgumentNullException(nameof(data), "Data must not be null."); }
            if (signature == null) { throw new ArgumentNullException(nameof(signature), "Signature must not be null."); }
            if (key.RawPublic == null) { throw new ArgumentNullException(nameof(key), "Unable to sign, public key in key must not be null."); }
            if (key.Type != KeyType.Identity) { throw new ArgumentException($"Unable to sign, wrong key type provided, got: {key.Type}, expected: KeyType.Identity."); }
            var rawSignature = Utility.FromBase64(signature);
            if (!SodiumPublicKeyAuth.VerifyDetached(rawSignature, Encoding.UTF8.GetBytes(data), key.RawPublic)) {
                throw new IntegrityException();
            }
        }

        public static Key GenerateKey(KeyType type)
        {
            if (type is KeyType.Encryption or KeyType.Authentication) {
                var secretKey = Utility.RandomBytes(Crypto.NbrSKeyBytes);
                return new Key(Guid.NewGuid(), type, secretKey, null);
            } else
            {
                var keypair = type switch
                {
                    KeyType.Identity => SodiumPublicKeyAuth.GenerateRevampedKeyPair(),
                    KeyType.Exchange => SodiumKeyExchange.GenerateRevampedKeyPair(),
                    _ => throw new ArgumentException("Unknown key type.", nameof(type))
                };
                return new Key(Guid.NewGuid(), 
                                type, 
                                keypair.PrivateKey,
                                keypair.PublicKey);
            }
        }

        #region -- KEY AGREEMENT --

        public static Key GenerateSharedSecret(Key clientKey, Key serverKey)
        {  
            if (clientKey.Version != serverKey.Version) { throw new KeyMismatchException("Unable to generate shared key, source keys from different versions."); }
            if (clientKey.Type != KeyType.Exchange || serverKey.Type != KeyType.Exchange) { throw new KeyMismatchException("Keys must be of type 'Exchange'."); }
            byte[] shared;
            if (clientKey.RawSecret != null) 
            {
                var clientSharedSecretBox = SodiumKeyExchange.CalculateClientSharedSecret(clientKey.RawPublic, clientKey.RawSecret, serverKey.RawPublic);
                shared = clientSharedSecretBox.TransferSharedSecret;
            } 
            else if (serverKey.RawSecret != null)
            {
                var serverSharedSecretBox = SodiumKeyExchange.CalculateServerSharedSecret(serverKey.RawPublic, serverKey.RawSecret, clientKey.RawPublic);
                shared = serverSharedSecretBox.ReadSharedSecret;
            }
            else
                throw new KeyMismatchException("Invalid keys provided.");
            return new Key(Guid.NewGuid(), KeyType.Encryption, shared, null);
        }

        #endregion

        #region -- ENCRYPTION/DECRYPTION --

        public static byte[] Encrypt(byte[] plainText, Key key)
        {
            if (plainText == null || plainText.Length == 0) { throw new ArgumentNullException(nameof(plainText), "Plain text to encrypt must not be null and not have a length of 0."); }
            if (key?.RawSecret == null) { throw new ArgumentNullException(nameof(key), "Key must not be null."); }
            var nonce = Utility.RandomBytes(Crypto.NbrNonceBytes);
            var cipherText = SodiumSecretBox.Create(plainText, nonce, key.RawSecret);
            return Utility.Combine(nonce, cipherText);
        }

        public static byte[] Decrypt(byte[] cipherText, Key key)
        {
            if (cipherText == null ||cipherText.Length == 0) { throw new ArgumentNullException(nameof(cipherText), "Cipher text to decrypt must not be null and not have a length of 0."); }
            if (key?.RawSecret == null) { throw new ArgumentNullException(nameof(key), "Key must not be null."); }
            var nonce = Utility.SubArray(cipherText, 0, Crypto.NbrNonceBytes);
            var data = Utility.SubArray(cipherText, Crypto.NbrNonceBytes);
            return SodiumSecretBox.Open(data, nonce, key.RawSecret);
        }

        #endregion

        #region -- HASHING --

        public static byte[] GenerateHash(string data)
        {
            return Crypto.GenerateHash(Encoding.UTF8.GetBytes(data));
        }

        public static byte[] GenerateHash(byte[] data)
        {
            return SodiumGenericHash.ComputeHash(Crypto.NbrHashBytes, data);
        }

        #endregion

        #region -- PRIVATE --

        private const int NbrSKeyBytes = 32;
        private const int NbrHashBytes = 32;
        private const int NbrNonceBytes = 24;

        #endregion

    }

}
