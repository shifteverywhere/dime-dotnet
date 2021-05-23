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
        public Guid id { get { return this.json.uid; } }
        public Guid subjectId { get { return this.json.sub; } }
        public Guid issuerId { get { return this.json.iss; } }
        public long issuedAt { get { return this.json.iat; } }
        public long expiresAt { get { return this.json.exp; } }
        public string exchangeKey { get { return this.json.xky; } }
        public string linkedTo { get { return this.json.lnk; } }
        public bool isImmutable { get; private set; } = false;

        public Message(Guid subjectId, Identity issuerIdentity, byte[] payload, long validFor)
        {
            if (!Crypto.SupportedProfile(issuerIdentity.profile)) { throw new UnsupportedProfileException(); }
            if (issuerIdentity == null || payload == null) { throw new NullReferenceException(); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (validFor <= 0) { throw new DateExpirationException("Message must be valid for at least 1 second."); }
            this.profile = issuerIdentity.profile;
            this.identity = issuerIdentity;
            this.payload = payload;
            this.json = new Message.JSONData(Guid.NewGuid(), subjectId, issuerIdentity.subjectId, now, (now + validFor));
        }

        public static Message Import(string encoded, Message linkedMessage = null)
        {
            if (!encoded.StartsWith(Message.HEADER)) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { '.' });
            if (components.Length != 5 && components.Length != 6) { throw new ArgumentException("Unexpected number of components found when decoding identity."); }
            int profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] identityBytes = Utility.FromBase64(components[1]);
            Identity identity = Identity.Import(System.Text.Encoding.UTF8.GetString(identityBytes, 0, identityBytes.Length));
            identity.VerifyTrust();
            string messagePart = encoded.Substring(0, encoded.LastIndexOf('.'));
            string signature = components[components.Length - 1];
            Message.JSONData parameters = JsonSerializer.Deserialize<Message.JSONData>(Utility.FromBase64(components[2]));
            Message message = new Message(identity, parameters, Utility.FromBase64(components[2]), profile);
            message.payload = Utility.FromBase64(components[3]);
            if(components.Length == 6)
            {
                message.state = Utility.FromBase64(components[4]);
            }
            message.encoded = messagePart;
            message.signature = signature;
            message.Verify(linkedMessage != null ? linkedMessage.Export() : null);
            message.isImmutable = true;
            return message;
        }

        public string Export(string issuerIdentityPrivateKey = null)
        {
            if (!this.isImmutable) {
                // TODO: encrypt payload here
                this.encoded = Encode();
                if (this.signature == null && issuerIdentityPrivateKey == null) { throw new NullReferenceException("Need private key to sign message for export."); }
                if (issuerIdentityPrivateKey != null)
                {
                    this.signature = Crypto.GenerateSignature(this.profile, this.encoded, issuerIdentityPrivateKey);
                    this.isImmutable = true;
                }
            }
            if (this.signature == null) { throw new IntegrityException("Missing signature."); }
            Crypto.VerifySignature(this.profile, this.encoded, this.signature, this.identity.identityKey);
            return this.encoded + "." + this.signature;
        }

        public bool HasSignature()
        {
            return (this.signature != null && this.signature.Length > 0);
        }

        public byte[] GetPayload(string exchangePrivateKey = null)
        {
            if (this.json.xky != null && exchangePrivateKey == null) { throw new ArgumentNullException("Private key must be provided for encrypted payload."); } 
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
        private byte[] payload { get; set; }
        private string signature;
        private string encoded;
        private struct JSONData
        {
            public Guid uid {get; set; }
            public Guid sub {get; set; }
            public Guid iss {get; set; }
            public long iat {get; set; }
            public long exp {get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string xky {get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string lnk {get; set; }

            //[JsonConstructor]
            public JSONData(Guid uid, Guid sub, Guid iss, long iat, long exp, string xky = null, string lnk = null)
            {
                if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp) { throw new ArgumentException("Expiration must be in the future."); }
                if (iat > exp) { throw new ArgumentException("Expiration must be after issue date."); }
                this.uid = uid;
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

        private void Verify(string linkedMessage = null)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (now < this.json.iat || now > this.json.exp) { throw new DateExpirationException(); }
            if (this.json.lnk != null && linkedMessage != null)
            {
                string msgHash = Crypto.GenerateHash(this.profile, linkedMessage);
                if (msgHash != this.json.lnk) { throw new IntegrityException("Linked message mismatch."); }
            }
            Crypto.VerifySignature(this.profile, this.Encode(), this.signature, this.identity.identityKey);
        }

    }

}
