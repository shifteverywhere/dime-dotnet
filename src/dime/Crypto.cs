using System;
using System.Text;
using NSec.Cryptography;

namespace ShiftEverywhere.DiME
{
    public class Crypto
    {
        public const int DEFUALT_PROFILE = 1;
        
        public static bool SupportedProfile(int profile)
        {
            return profile == Crypto.DEFUALT_PROFILE;
        }
        
        public static string GenerateSignature(int version, string data, string privateIdentityKey)
        {
                if ( version != 1 ) { throw new NotSupportedException(); }
                if ( privateIdentityKey == null ) { throw new ArgumentNullException(); }
                Key key = Key.Import(SignatureAlgorithm.Ed25519, Utility.FromBase64(privateIdentityKey), KeyBlobFormat.PkixPrivateKey);
                byte[] signature = SignatureAlgorithm.Ed25519.Sign(key, Encoding.UTF8.GetBytes(data));
                return System.Convert.ToBase64String(signature).Trim('=');
        }

        public static bool VerifySignature(int version, string data, string signature, string publicIdentityKey)
        {
            if ( version != 1 ) { throw new NotSupportedException(); }
            if ( publicIdentityKey == null ) { throw new ArgumentNullException(); }
            PublicKey verifyKey = PublicKey.Import(SignatureAlgorithm.Ed25519, Utility.FromBase64(publicIdentityKey), KeyBlobFormat.PkixPublicKey);
            return SignatureAlgorithm.Ed25519.Verify(verifyKey, Encoding.UTF8.GetBytes(data), Utility.FromBase64(signature));
        }

        public static Keypair GenerateKeyPair(int version, KeypairType type)
        {
            if ( version != 1 ) { throw new NotSupportedException(); }
            Key key;
            KeyCreationParameters parameters = new KeyCreationParameters();
            parameters.ExportPolicy = KeyExportPolicies.AllowPlaintextExport;
            switch ( type )
            {
                case KeypairType.IdentityKey:
                    key = new Key(SignatureAlgorithm.Ed25519, parameters);
                    break;
                case KeypairType.ExchangeKey:
                    key = new Key(KeyAgreementAlgorithm.X25519, parameters);
                    break;
                default:
                    throw new NotSupportedException();
            }
            if ( key != null ) 
            {
                return new Keypair(type, 
                                   Crypto.ExportKey(key, KeyBlobFormat.PkixPublicKey), 
                                   Crypto.ExportKey(key, KeyBlobFormat.PkixPrivateKey));
            }
            throw new Exception();
        }

        public static string GenerateHash(int version, string data)
        {
            if ( version != 1 ) { throw new NotSupportedException(); }
            return Utility.ToHex(HashAlgorithm.Blake2b_256.Hash(Encoding.UTF8.GetBytes(data)));
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
