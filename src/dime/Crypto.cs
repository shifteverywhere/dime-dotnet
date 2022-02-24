//
//  Crypto.cs
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using ASodium;

namespace DiME
{
    /// <summary>
    /// Cryptographic helper methods, which also abstracts the rest of the implementation from any underlying
    /// cryptographic library used.
    /// </summary>
    public static class Crypto
    {
        /// <summary>
        /// Generates a cryptographic signature from a data string.
        /// </summary>
        /// <param name="data">The string to sign.</param>
        /// <param name="key">The key to use for the signature.</param>
        /// <returns>The signature that was generated, encoded in Base 64.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public static string GenerateSignature(string data, Key key)
        {
            if (key == null) { throw new ArgumentNullException(nameof(key), "Unable to sign, key must not be null."); }
            if (key.RawSecret == null) { throw new ArgumentNullException(nameof(key), "Unable to sign, key in key must not be null."); }
            if (key.Type != KeyType.Identity) { throw new ArgumentException($"Unable to sign, wrong key type provided, got: {key.Type}, expected: KeyType.Identity."); }
            var signature = SodiumPublicKeyAuth.SignDetached(Encoding.UTF8.GetBytes(data), key.RawSecret);
            return Utility.ToBase64(signature);
        }

        /// <summary>
        /// Verifies a cryptographic signature for a data string.
        /// </summary>
        /// <param name="data">The string that should be verified with the signature.</param>
        /// <param name="signature">The signature that should be verified.</param>
        /// <param name="key">The key that should be used for the verification.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        /// <exception cref="IntegrityException">If the signature could not be verified.</exception>
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

        /// <summary>
        /// Generates a cryptographic key of a provided type.
        /// </summary>
        /// <param name="type">The type of the key to generate.</param>
        /// <returns>The generated key.</returns>
        /// <exception cref="ArgumentException"></exception>
        public static Key GenerateKey(KeyType type)
        {
            if (type is KeyType.Encryption or KeyType.Authentication) {
                var secretKey = Utility.RandomBytes(NbrSKeyBytes);
                return new Key(Guid.NewGuid(), type, secretKey, null);
            }
            // If it wasn't Encryption or Authentication generation continues here
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

        #region -- KEY AGREEMENT --

        /// <summary>
        /// Generates a shared secret from two keys of type EXCHANGE. The initiator of the key exchange is always the
        /// server and the receiver of the key exchange is always the client (no matter on which side this method is
        /// called). The returned key will be of type ENCRYPTION.
        /// </summary>
        /// <param name="clientKey">The client key to use (the receiver of the exchange).</param>
        /// <param name="serverKey">The server key to use (the initiator of the exchange).</param>
        /// <returns>The generated shared secret key.</returns>
        /// <exception cref="KeyMismatchException">If provided keys are of the wrong type.</exception>
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

        /// <summary>
        /// Encrypts a plain text byte array using the provided key.
        /// </summary>
        /// <param name="plainText">The byte array to encrypt.</param>
        /// <param name="key">The key to use for the encryption.</param>
        /// <returns>The encrypted cipher text.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Encrypt(byte[] plainText, Key key)
        {
            if (plainText == null || plainText.Length == 0) { throw new ArgumentNullException(nameof(plainText), "Plain text to encrypt must not be null and not have a length of 0."); }
            if (key?.RawSecret == null) { throw new ArgumentNullException(nameof(key), "Key must not be null."); }
            var nonce = Utility.RandomBytes(NbrNonceBytes);
            var cipherText = SodiumSecretBox.Create(plainText, nonce, key.RawSecret);
            return Utility.Combine(nonce, cipherText);
        }

        /// <summary>
        /// Decrypts a cipher text byte array using the provided key.
        /// </summary>
        /// <param name="cipherText">The byte array to decrypt.</param>
        /// <param name="key">The key to use for the decryption.</param>
        /// <returns>The decrypted plain text.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        public static byte[] Decrypt(byte[] cipherText, Key key)
        {
            if (cipherText == null ||cipherText.Length == 0) { throw new ArgumentNullException(nameof(cipherText), "Cipher text to decrypt must not be null and not have a length of 0."); }
            if (key?.RawSecret == null) { throw new ArgumentNullException(nameof(key), "Key must not be null."); }
            var nonce = Utility.SubArray(cipherText, 0, NbrNonceBytes);
            var data = Utility.SubArray(cipherText, NbrNonceBytes);
            return SodiumSecretBox.Open(data, nonce, key.RawSecret);
        }

        #endregion

        #region -- HASHING --

        /// <summary>
        /// Generates a secure hash of a string.
        /// </summary>
        /// <param name="data">The data that should be hashed.</param>
        /// <returns>The generated secure hash.</returns>
        public static byte[] GenerateHash(string data)
        {
            return GenerateHash(Encoding.UTF8.GetBytes(data));
        }

        /// <summary>
        /// Generates a secure hash of a byte array.
        /// </summary>
        /// <param name="data">The data that should be hashed.</param>
        /// <returns>The generated secure hash.</returns>
        public static byte[] GenerateHash(byte[] data)
        {
            return SodiumGenericHash.ComputeHash(NbrHashBytes, data);
        }

        #endregion

        #region -- PRIVATE --

        private const int NbrSKeyBytes = 32;
        private const int NbrHashBytes = 32;
        private const int NbrNonceBytes = 24;

        #endregion

    }

}
