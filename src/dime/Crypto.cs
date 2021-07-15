//
//  Crypto.cs
//  DiME - Digital Identity Message Envelope
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
        public const Profile DEFUALT_PROFILE = Profile.Uno;
        
        public static bool SupportedProfile(Profile profile)
        {
            return profile == Crypto.DEFUALT_PROFILE;
        }
        
        public static string GenerateSignature(string data, KeyBox keybox)
        {
            if (!Crypto.SupportedProfile(keybox.Profile)) { throw new NotSupportedException(); }
            if (keybox == null) { throw new ArgumentNullException(nameof(keybox), "Unable to sign, keybox must not be null."); }
            if (keybox.RawKey == null) { throw new ArgumentNullException(nameof(keybox), "Unable to sign, key in keybox must not be null."); }
            if (keybox.Type != KeyType.Identity) { throw new ArgumentException($"Unable to sign, wrong key type provided, got: {keybox.Type}, expected: KeyType.Identity."); }
            Key key = Key.Import(SignatureAlgorithm.Ed25519, keybox.RawKey, KeyBlobFormat.RawPrivateKey);
            byte[] rawSignature = SignatureAlgorithm.Ed25519.Sign(key, Encoding.UTF8.GetBytes(data));
            return System.Convert.ToBase64String(Utility.Prefix((byte)keybox.Profile, rawSignature)).Trim('=');
        }

        public static void VerifySignature(string data, string signature, KeyBox keybox)
        {
            if (!Crypto.SupportedProfile(keybox.Profile)) { throw new UnsupportedProfileException(); }
            if (data == null) { throw new ArgumentNullException(nameof(data), "Data must not be null."); }
            if (signature == null) { throw new ArgumentNullException(nameof(signature), "Signature must not be null."); }
            if (keybox == null) { throw new ArgumentNullException(nameof(keybox), "Unable to verify signature, keybox must not be null."); }
            if (keybox.RawPublicKey == null) { throw new ArgumentNullException(nameof(keybox), "Unable to sign, public key in keybox must not be null."); }
            if (keybox.Type != KeyType.Identity) { throw new ArgumentException($"Unable to sign, wrong key type provided, got: {keybox.Type}, expected: KeyType.Identity."); }
            byte[] rawSignature = Utility.FromBase64(signature);
            if ((Profile)rawSignature[0] != keybox.Profile) { throw new KeyMissmatchException("Signature profile does not match key profile version."); }
            PublicKey verifyKey = PublicKey.Import(SignatureAlgorithm.Ed25519, keybox.RawPublicKey, KeyBlobFormat.RawPublicKey);
            if (!SignatureAlgorithm.Ed25519.Verify(verifyKey, Encoding.UTF8.GetBytes(data), Utility.SubArray(rawSignature, 1)))
            {
                throw new IntegrityException();
            }
        }

        public static KeyBox GenerateKeyPair(Profile profile, KeyType type)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            Key key;
            KeyCreationParameters parameters = new KeyCreationParameters();
            parameters.ExportPolicy = KeyExportPolicies.AllowPlaintextExport;
            switch (type)
            {
                case KeyType.Identity:
                    key = new Key(SignatureAlgorithm.Ed25519, parameters);
                    break;
                case KeyType.Exchange:
                    key = new Key(KeyAgreementAlgorithm.X25519, parameters);
                    break;
                default:
                    throw new NotSupportedException("Unkown keypair type.");
            }
            return new KeyBox(Guid.NewGuid(), 
                               type, 
                               Crypto.ExportKey(key, KeyBlobFormat.RawPrivateKey),
                               Crypto.ExportKey(key, KeyBlobFormat.RawPublicKey),
                               profile);
        }

        public static string GenerateHash(Profile profile, string data)
        {
            return Crypto.GenerateHash(profile, Encoding.UTF8.GetBytes(data));
        }

        public static string GenerateHash(Profile profile, byte[] data)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            return Utility.ToHex(HashAlgorithm.Blake2b_256.Hash(data));
        }

        private static byte[] ExportKey(Key key, KeyBlobFormat keyBlobFormat)
        {
            var blob = new byte[key.GetExportBlobSize(keyBlobFormat)];
            var blobSpan = new Span<byte>(blob);
            int blobSize = 0;
            key.TryExport(keyBlobFormat, blobSpan, out blobSize);
            return blob;
        }

        private static byte[] GetKey(string key)
        {
            string[] keyComponents = key.Split(new char[] { Envelope._SECTION_DELIMITER });
            Profile profile; 
            if (!Enum.TryParse<Profile>(keyComponents[0], out profile)) { throw new DataFormatException("Unable to determine key profile version, invalid data format."); }
            if (!SupportedProfile(profile)) { return null; } // TODO: replace crypto impl.
            return Utility.FromBase64(keyComponents[2]);
        } 

    }

}
