using System.Text.Json;

namespace ShiftEverywhere.DiME
{
    public enum KeypairType: int
    {
        Unknown = 0,
        IdentityKey = 1,
        ExchangeKey = 2
    }

    public struct Keypair
    {
        public KeypairType type { get; private set; }
        public string publicKey { get; private set; }
        public string privateKey { get; private set; }

        public Keypair(KeypairType type, string publicKey, string privateKey)
        {
            this.type = type;
            this.publicKey = publicKey;
            this.privateKey = privateKey;            
        }

        public static Keypair GenerateKeypair(KeypairType type, int version = 1)
        {
            return Crypto.GenerateKeyPair(version, type);
        }

        public static Keypair ImportFromJSON(string json)
        {
            return JsonSerializer.Deserialize<Keypair>(json);
        }

        public string ExportToJSON() 
        {
            return JsonSerializer.Serialize(this);
        } 

    }

}