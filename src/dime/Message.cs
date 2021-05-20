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
        public Guid subjectId { get { return this.json.sub; } }
        public Guid issuerId { get { return this.json.iss; } }
        public long issuedAt { get { return this.json.iat; } }
        public long expiresAt { get { return this.json.exp; } }
        public string exchangeKey { get { return this.json.xky; } }
        public string linkedTo { get { return this.json.lnk; } }

        public Message(Guid subjectId, Identity issuerIdentity, string issuerIdentityPrivateKey, byte[] payload, long expiresAt, string subjectExchangeKey = null,  Keypair? issuerExchangeKeypair = null, string linkedTo = null, int profile = Crypto.DEFUALT_PROFILE)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
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
            this.json = new Message.JSONData(subjectId, issuerIdentity.subjectId, now, expiresAt, linkedTo, exchangeKey);
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
                if (!Crypto.VerifySignature(profile, messagePart, signature, identity.identityKey))
                {
                    throw new ArgumentNullException("Unable to verify message signature."); // TODO: throw more specific exception
                }
                Message.JSONData parameters = JsonSerializer.Deserialize<Message.JSONData>(Utility.FromBase64(components[2]));
                Message message = new Message(identity, parameters, Utility.FromBase64(components[2]), profile);
                message.payload = Utility.FromBase64(components[3]);
                if(components.Length == 6)
                {
                    message.state = Utility.FromBase64(components[4]);
                }
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
            if (now >= this.json.iat && now < this.json.exp)
            {
                if (this.json.lnk != null && linkedMessage != null)
                {
                    string msgHash = Crypto.GenerateHash(this.profile, linkedMessage);
                    if (msgHash != this.json.lnk) { throw new ArgumentException("Linked message mismatch."); } // TODO throw another exception
                }
                return Crypto.VerifySignature(this.profile, this.Encode(), this.signature, this.identity.identityKey); // TODO: throw exception
            }
            return false; // TODO: throw exception
        }

        public byte[] GetPayload(string exchangePrivateKey = null)
        {
            if (this.json.xky != null && exchangePrivateKey == null) { throw new ArgumentException("Payload is encrypted."); } // TODO: another exception
            if (this.json.xky != null)
            {
                // TODO: decrypt payload
                return this.payload;
            }
            return this.payload;
        }

        public void LinkMessage(Message message)
        {
            if (this.isImmutable) { throw new ArgumentException("Message is immutable and cannot be changed."); } // TODO: another exception
            if (message == null) { throw new ArgumentException("Message to link must not be null."); }
            this.json.lnk = Crypto.GenerateHash(this.profile, message.Export());
        }

        /* PRIVATE */
        private const string HEADER = "M";
        private string signature;
        private string issuerIdentityPrivateKey;
        private string subjectExchangeKey;
        private Keypair? issuerExchangeKeypair;
        private string encoded;
        private bool isImmutable = false;
        private struct JSONData
        {
            public Guid sub;
            public Guid iss;
            public long iat;
            public long exp;
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string xky;
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string lnk;

            public JSONData(Guid sub, Guid iss, long iat, long exp, string xky, string lnk)
            {
                if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp) { throw new ArgumentException("Expires at is earlier than now."); } // TODO: throw other exception
                if (iat > exp) { throw new ArgumentException("Expires at is earlier than issued at."); }
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
                this.xky = xky;
                this.lnk = lnk;
            }
        }
        private Message.JSONData json;

        private Message(Identity issuerIdentity, Message.JSONData parameters, byte[] payload, int profile = Crypto.DEFUALT_PROFILE)
        {
            if ( issuerIdentity == null || payload == null ) { throw new ArgumentNullException(); }
            this.identity = issuerIdentity;
            this.identity = issuerIdentity;
            this.json = parameters;
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
                                    Utility.ToBase64(JsonSerializer.Serialize(this.json)));
                if ( this.json.xky != null )
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
