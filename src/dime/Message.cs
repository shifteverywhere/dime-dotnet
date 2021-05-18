using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public class Message
    {
        /* PUBLIC */
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public int profile { get; private set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public Identity identity { get; private set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public byte[] state;
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public byte[] payload { get; private set; }
        [JsonIgnore(Condition = JsonIgnoreCondition.Always)]
        public string signature { get; private set; }
        [JsonPropertyName("sub")]
        public Guid subjectId { get; private set; }
        [JsonPropertyName("iss")]
        public Guid issuerId { get; private set; }
        [JsonPropertyName("iat")]
        public long issuedAt { get; private set; }
        [JsonPropertyName("lnk")]
        public string linkedTo { get; private set; }
        [JsonPropertyName("exp")]
        public long expiresAt { get; private set; }
        [JsonPropertyName("xky")][JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string exchangeKey { get; private set; }

        public Message(Guid subjectId, Identity identity, byte[] payload, long expiresAt, int profile = Crypto.DEFUALT_PROFILE)
        {
            if ( identity == null || payload == null ) { throw new ArgumentNullException(); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if ( expiresAt <= now ) { throw new ArgumentException("Expiration date must be in the future."); }
            this.profile = profile;
            this.identity = identity;
            this.payload = payload;
            this.issuedAt = now;
            this.expiresAt = expiresAt;
            this.issuerId = identity.subjectId;
            this.subjectId = subjectId;
        }

        [JsonConstructor]
        public Message(Guid subjectId, Guid issuerId, long issuedAt, long expiresAt, string linkedTo, string exchangeKey)
        {
            this.subjectId = subjectId;
            this.issuerId = issuerId;
            this.issuedAt = issuedAt;
            this.expiresAt = expiresAt;
            this.linkedTo = linkedTo;
            this.exchangeKey = exchangeKey;
            this.profile = Crypto.DEFUALT_PROFILE;
        }

        public Message(Guid subjectId, string jsonIdentity, byte[] message, long expiresAt, int profile = Crypto.DEFUALT_PROFILE) : this(subjectId, Identity.Import(jsonIdentity), message, expiresAt, profile) { }

        public static Message Import(string encoded, string exchangePrivateKey = null)
        {
            if ( !encoded.StartsWith(Message.HEADER) ) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(".");
            if ( components.Length != 5 && components.Length != 6 ) { throw new ArgumentException("Unexpected number of components found then decoding identity."); }
            int profile = int.Parse(components[0].Substring(1));
            if ( !Crypto.SupportedProfile(profile) ) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] identityBytes = Utility.FromBase64(components[1]);
            Identity identity = Identity.Import(System.Text.Encoding.UTF8.GetString(identityBytes, 0, identityBytes.Length));
            if ( identity.VerifyTrust() )
            {
                string messagePart = encoded.Substring(0, encoded.LastIndexOf('.'));
                string signature = components[components.Length - 1];
                if ( Crypto.VerifySignature(profile, messagePart, signature, identity.identityKey) )
                {
                    throw new ArgumentNullException("Unable to verify message signature."); // TODO: throw more specific exception
                }
                byte[] json = Utility.FromBase64(components[2]);
                Message message = JsonSerializer.Deserialize<Message>(json);
                message.identity = identity;
                message.payload = Utility.FromBase64(components[2]);; // TODO: decrypt it if needed
                message.encoded = messagePart;
                message.signature = signature;
                return message;
            }
            throw new ArgumentNullException("Untrusted identity."); // TODO: throw more specific exception
        }

        public string Export(string identityPrivateKey)
        {
            if ( this.signature == null )
            {
                this.signature = Crypto.GenerateSignature(this.profile, Encode(), identityPrivateKey);
            }
            return Encode() + "." + this.signature;
        }

        public string Export(string receiverExchangeKey, Keypair exchangeKeypair, string identityPrivateKey)
        {
            this.exchangeKey = receiverExchangeKey;
            // TODO: encrypt payload here
            return Export(identityPrivateKey);
        }

        public bool Verify()
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if ( now >= this.issuedAt && now < this.expiresAt )
            {
                return Crypto.VerifySignature(this.profile, this.Encode(), this.signature, this.identity.identityKey); // TODO: throw exception
            }
            return false; // TODO: throw exception
        }

        /* PRIVATE */
        private const string HEADER = "M";
        private string encoded;
        private string Encode()
        {
            if ( this.encoded == null ) 
            {  
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}.{3}", 
                                    Message.HEADER,
                                    this.profile,
                                    Utility.ToBase64(this.identity.Export()),
                                    Utility.ToBase64(JsonSerializer.Serialize(this)));
                if ( this.exchangeKey != null )
                {
                    // TODO: encrypt payplaod
                    builder.AppendFormat(".{0}", Utility.ToBase64(this.payload));
                }
                else
                {
                    builder.AppendFormat(".{0}", Utility.ToBase64(this.payload));
                }
                if ( this.state != null)
                {
                    builder.AppendFormat(".{0}", Utility.ToBase64(this.state));
                }
                this.encoded = builder.ToString();
            }
            return this.encoded;
        }

    }

}
