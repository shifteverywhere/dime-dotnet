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
        public const ProfileVersion DEFUALT_PROFILE = ProfileVersion.One;
        
        public static bool SupportedProfile(ProfileVersion profile)
        {
            return profile == Crypto.DEFUALT_PROFILE;
        }
        
        public static string GenerateSignature(ProfileVersion profile, string data, string privateKey)
        {
                if (!Crypto.SupportedProfile(profile)) { throw new NotSupportedException(); }
                if (privateKey == null) { throw new ArgumentNullException(nameof(privateKey), "Unable to sign, provided private key is null."); }
                Key key = Key.Import(SignatureAlgorithm.Ed25519, Utility.FromBase64(privateKey), KeyBlobFormat.PkixPrivateKey);
                byte[] signature = SignatureAlgorithm.Ed25519.Sign(key, Encoding.UTF8.GetBytes(data));
                return System.Convert.ToBase64String(signature).Trim('=');
        }

        public static void VerifySignature(ProfileVersion profile, string data, string signature, string publicIdentityKey)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            if (publicIdentityKey == null) { throw new ArgumentNullException(nameof(publicIdentityKey), "Unable to verify signature, provided public key is null."); }
            PublicKey verifyKey = PublicKey.Import(SignatureAlgorithm.Ed25519, Utility.FromBase64(publicIdentityKey), KeyBlobFormat.PkixPublicKey);
            if (!SignatureAlgorithm.Ed25519.Verify(verifyKey, Encoding.UTF8.GetBytes(data), Utility.FromBase64(signature)))
            {
                throw new IntegrityException();
            }
        }

        public static KeyBox GenerateKeyPair(ProfileVersion profile, KeyType type)
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
                               Crypto.ExportKey(key, KeyBlobFormat.PkixPrivateKey),
                               Crypto.ExportKey(key, KeyBlobFormat.PkixPublicKey),
                               profile);
        }

        public static string GenerateHash(ProfileVersion profile, string data)
        {
            return Crypto.GenerateHash(profile, Encoding.UTF8.GetBytes(data));
        }

        public static string GenerateHash(ProfileVersion profile, byte[] data)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException(); }
            return Utility.ToHex(HashAlgorithm.Blake2b_256.Hash(data));
        }

        private static string ExportKey(Key key, KeyBlobFormat keyBlobFormat)
        {
            var blob = new byte[key.GetExportBlobSize(keyBlobFormat)];
            var blobSpan = new Span<byte>(blob);
            int blobSize = 0;
            key.TryExport(keyBlobFormat, blobSpan, out blobSize);
            string base64 = System.Convert.ToBase64String(blob);
            return base64.Trim('=');
        }

    }

}
