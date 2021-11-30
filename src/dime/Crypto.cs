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
using NSec.Cryptography;

namespace ShiftEverywhere.DiME
{
    public static class Crypto
    {
        
        public static string GenerateSignature(string data, Key key)
        {
            if (key == null) { throw new ArgumentNullException(nameof(key), "Unable to sign, keybox must not be null."); }
            if (key.RawKey == null) { throw new ArgumentNullException(nameof(key), "Unable to sign, key in keybox must not be null."); }
            if (key.Type != KeyType.Identity) { throw new ArgumentException($"Unable to sign, wrong key type provided, got: {key.Type}, expected: KeyType.Identity."); }
            NSec.Cryptography.Key secretKey = NSec.Cryptography.Key.Import(SignatureAlgorithm.Ed25519, key.RawKey, KeyBlobFormat.RawPrivateKey);
            byte[] signature = SignatureAlgorithm.Ed25519.Sign(secretKey, Encoding.UTF8.GetBytes(data));
            return Utility.ToBase64(signature);
        }

        public static void VerifySignature(string data, string signature, Key key)
        {
            if (key == null) { throw new ArgumentNullException(nameof(key), "Unable to verify signature, keybox must not be null."); }
            if (data == null) { throw new ArgumentNullException(nameof(data), "Data must not be null."); }
            if (signature == null) { throw new ArgumentNullException(nameof(signature), "Signature must not be null."); }
            if (key.RawPublicKey == null) { throw new ArgumentNullException(nameof(key), "Unable to sign, public key in keybox must not be null."); }
            if (key.Type != KeyType.Identity) { throw new ArgumentException($"Unable to sign, wrong key type provided, got: {key.Type}, expected: KeyType.Identity."); }
            byte[] rawSignature = Utility.FromBase64(signature);
            PublicKey verifyKey = PublicKey.Import(SignatureAlgorithm.Ed25519, key.RawPublicKey, KeyBlobFormat.RawPublicKey);
            if (!SignatureAlgorithm.Ed25519.Verify(verifyKey, Encoding.UTF8.GetBytes(data), Utility.SubArray(rawSignature, 1)))
            {
                throw new IntegrityException();
            }
        }

        public static Key GenerateKey(KeyType type)
        {
            NSec.Cryptography.Key key;
            KeyCreationParameters parameters = new KeyCreationParameters();
            parameters.ExportPolicy = KeyExportPolicies.AllowPlaintextExport;
            switch (type)
            {
                case KeyType.Identity:
                    key = new NSec.Cryptography.Key(SignatureAlgorithm.Ed25519, parameters);
                    break;
                case KeyType.Exchange:
                    key = new NSec.Cryptography.Key(KeyAgreementAlgorithm.X25519, parameters);
                    break;
                default:
                    throw new ArgumentException("Unkown key type.", nameof(type));
            }
            return new Key(Guid.NewGuid(), 
                               type, 
                               Crypto.ExportKey(key, KeyBlobFormat.RawPrivateKey),
                               Crypto.ExportKey(key, KeyBlobFormat.RawPublicKey));
        }

        #region -- KEY AGREEMENT --

        public static NSec.Cryptography.Key GenerateSharedSecret(Key localKey, Key remoteKey, byte[] salt, byte[] info)
        {  
            if (localKey.Type != KeyType.Exchange || remoteKey.Type != KeyType.Exchange) { throw new KeyMismatchException("Keys must be of type 'Exchange'."); }
            NSec.Cryptography.Key privateKey = NSec.Cryptography.Key.Import(KeyAgreementAlgorithm.X25519, localKey.RawKey, KeyBlobFormat.RawPrivateKey);
            PublicKey publicKey = PublicKey.Import(KeyAgreementAlgorithm.X25519, remoteKey.RawPublicKey, KeyBlobFormat.RawPublicKey);
            SharedSecret shared = KeyAgreementAlgorithm.X25519.Agree(privateKey, publicKey);
            return KeyDerivationAlgorithm.HkdfSha256.DeriveKey(shared, salt, info, AeadAlgorithm.ChaCha20Poly1305);  
        }

        #endregion

        #region -- ENCRYPTION/DECRYPTION --

        public static byte[] Encrypt(byte[] plainText, NSec.Cryptography.Key key)     
        {
            if (plainText == null || plainText.Length == 0) { throw new ArgumentNullException(nameof(plainText), "Plain text to encrypt must not be null and not have a length of 0."); }
            if (key == null) { throw new ArgumentNullException(nameof(key), "Key must not be null."); }
            byte[] nonce = Utility.RandomBytes(12);
            byte[] cipherText = AeadAlgorithm.ChaCha20Poly1305.Encrypt(key, nonce, null, plainText);
            return Utility.Combine(nonce, cipherText);
        }

        public static byte[] Decrypt(byte[] cipherText, NSec.Cryptography.Key key)
        {
            if (cipherText == null ||cipherText.Length == 0) { throw new ArgumentNullException(nameof(cipherText), "Cipher text to decrypt must not be null and not have a length of 0."); }
            if (key == null) { throw new ArgumentNullException(nameof(key), "Key must not be null."); }
            byte[] nonce = Utility.SubArray(cipherText, 1, 12);
            byte[] data = Utility.SubArray(cipherText, 13);
            return AeadAlgorithm.ChaCha20Poly1305.Decrypt(key, nonce, null, data);
        }

        #endregion

        #region -- HASHING --

        public static byte[] GenerateHash(string data)
        {
            return Crypto.GenerateHash(Encoding.UTF8.GetBytes(data));
        }

        public static byte[] GenerateHash(byte[] data)
        {
            return HashAlgorithm.Blake2b_256.Hash(data);
        }

        #endregion

        private static byte[] ExportKey(NSec.Cryptography.Key key, KeyBlobFormat keyBlobFormat)
        {
            var blob = new byte[key.GetExportBlobSize(keyBlobFormat)];
            var blobSpan = new Span<byte>(blob);
            int blobSize = 0;
            key.TryExport(keyBlobFormat, blobSpan, out blobSize);
            return blob;
        }

    }

}
