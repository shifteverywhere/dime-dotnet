using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public class Message
    {
        /* PUBLIC */
        public int profile { get; private set; }
        public Identity identity { get; private set; }
        public byte[] state;
        public byte[] payload { get; private set; }

        public struct Parameters
        {
            [JsonPropertyName("sub")]
            public Guid subjectId { get; internal set; }
            [JsonPropertyName("iss")]
            public Guid issuerId { get; internal set; }
            [JsonPropertyName("iat")]
            public long issuedAt { get; internal set; }
            [JsonPropertyName("exp")]
            public long expiresAt { get; internal set; }
            [JsonPropertyName("xky")][JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string exchangeKey { get; internal set; }
            [JsonPropertyName("lnk")][JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string linkedTo { get; internal set; }

            public Parameters(Guid subjectId, Guid issuerId, long issuedAt, long expiresAt, string exchangeKey, string linkedTo)
            {
                if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > expiresAt) { throw new ArgumentException("Expires at is earlier than now."); } // TODO: throw other exception
                if (issuedAt < expiresAt) { throw new ArgumentException("Expires at is earlier than issued at."); }
                this.subjectId = subjectId;
                this.issuerId = issuerId;
                this.issuedAt = issuedAt;
                this.expiresAt = expiresAt;
                this.exchangeKey = exchangeKey;
                this.linkedTo = linkedTo;
            }
        }
        public Message.Parameters parameters; // TODO: should be read only

        public Message(Guid subjectId, Identity issuerIdentity, string issuerIdentityPrivateKey, byte[] payload, long expiresAt, string subjectExchangeKey = null,  Keypair? issuerExchangeKeypair = null, string linkedTo = null, int profile = Crypto.DEFUALT_PROFILE)
        {
            if ( issuerIdentity == null || issuerIdentityPrivateKey == null || payload == null ) { throw new ArgumentNullException(); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if ( expiresAt <= now ) { throw new ArgumentException("Expiration date must be in the future."); }
            this.profile = profile;
            this.identity = issuerIdentity;
            this.issuerIdentityPrivateKey = issuerIdentityPrivateKey;
            this.payload = payload;
            this.issuerExchangeKeypair = issuerExchangeKeypair;
            this.subjectExchangeKey = subjectExchangeKey;
            string exchangeKey = issuerExchangeKeypair.HasValue ? (issuerExchangeKeypair.Value).publicKey : null;
            this.parameters = new Message.Parameters(subjectId, issuerIdentity.subjectId, now, expiresAt, linkedTo, exchangeKey);
        }

        public static Message Import(string encoded)
        {
            if ( !encoded.StartsWith(Message.HEADER) ) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(".");
            if ( components.Length != 5 && components.Length != 6 ) { throw new ArgumentException("Unexpected number of components found when decoding identity."); }
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
                Message.Parameters parameters = JsonSerializer.Deserialize<Message.Parameters>(Utility.FromBase64(components[2]));
                Message message = new Message(identity, parameters, Utility.FromBase64(components[2]), profile);
                message.encoded = messagePart;
                message.signature = signature;
                message.isImmutable = true;
                return message;
            }
            throw new ArgumentNullException("Untrusted identity."); // TODO: throw more specific exception
        }

        public string Export()
        {
            if (!this.isImmutable) {
                this.encoded = Encode();
                if (this.issuerIdentityPrivateKey == null) { throw new ArgumentException("Unable to create signature (missing private key)."); } // TODO: another exception
                 // TODO: encrypt payload here
                this.signature = Crypto.GenerateSignature(this.profile, Encode(), this.issuerIdentityPrivateKey);
                this.isImmutable = true;
            }
            if (this.signature == null) { throw new ArgumentException("Missing signature (unexpected error)."); } // TODO: another exception
            return this.encoded + "." + this.signature;
        }

        public bool Verify(string linkedMessage = null)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now >= this.parameters.issuedAt && now < this.parameters.expiresAt)
            {
                if (this.parameters.linkedTo != null && linkedMessage != null)
                {
                    string msgHash = Crypto.GenerateHash(this.profile, linkedMessage);
                    if (msgHash != this.parameters.linkedTo) { throw new ArgumentException("Linked message mismatch."); } // TODO throw another exception
                }
                return Crypto.VerifySignature(this.profile, this.Encode(), this.signature, this.identity.identityKey); // TODO: throw exception
            }
            return false; // TODO: throw exception
        }

        public byte[] GetPayload(string exchangePrivateKey = null)
        {
            if (this.parameters.exchangeKey != null && exchangePrivateKey == null) { throw new ArgumentException("Payload is encrypted."); } // TODO: another exception
            if (this.parameters.exchangeKey != null)
            {
                // TODO: decrypt payload
                return this.payload;
            }
            return this.payload;
        }

        public void LinkMessage(string encodedMessage)
        {
            if (this.isImmutable) { throw new ArgumentException("Message is immutable and cannot be changed."); } // TODO: another exception
            if (encodedMessage == null) { throw new ArgumentException("Message to link must not be null."); }
            this.parameters.linkedTo = Crypto.GenerateHash(this.profile, encodedMessage);
        }

        /* PRIVATE */
        private const string HEADER = "M";
        private string signature;
        private string issuerIdentityPrivateKey;
        private string subjectExchangeKey;
        private Keypair? issuerExchangeKeypair;
        private string encoded;
        private bool isImmutable = false;

        private Message(Identity issuerIdentity, Message.Parameters parameters, byte[] payload, int profile = Crypto.DEFUALT_PROFILE)
        {
            if ( issuerIdentity == null || payload == null ) { throw new ArgumentNullException(); }
            this.identity = issuerIdentity;
            this.identity = issuerIdentity;
            this.parameters = parameters;
            this.payload = payload;
            this.profile = profile;
        }

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
                if ( this.parameters.exchangeKey != null )
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
