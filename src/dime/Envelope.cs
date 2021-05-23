using System;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;

namespace ShiftEverywhere.DiME
{
    public class Envelope
    {
        /* PUBLIC */
        public int profile { get; private set; }
        public Identity identity { get; set; }
        public List<Message> messages { get; private set; }
        public Guid subjectId { get { return this.json.sub; } }
        public Guid issuerId { get { return this.json.iss; } }
        public long issuedAt { get { return this.json.iat; } }
        public long expiresAt { get { return this.json.exp; } }
        public bool isImmutable { get; private set; } = false;

        public Envelope(Identity issuerIdentity, Guid subjectId, long issuedAt, long expiresAt, int profile = Crypto.DEFUALT_PROFILE)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            this.identity = issuerIdentity;
            this.json = new JSONData(Guid.NewGuid(), subjectId, issuerIdentity.subjectId, issuedAt, expiresAt);
            this.profile = profile;
        }

        public static Envelope Import(string encoded)
        {
            if (!encoded.StartsWith(Envelope.HEADER)) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { '.' });
            if (components.Length != 5) { throw new ArgumentException("Unexpected number of components found then decoding identity."); }
            int profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] identityBytes = Utility.FromBase64(components[1]);
            Identity identity = Identity.Import(System.Text.Encoding.UTF8.GetString(identityBytes, 0, identityBytes.Length));
            identity.VerifyTrust();
            string envPart = encoded.Substring(0, encoded.LastIndexOf('.'));
            string signature = components[components.Length - 1];
            Crypto.VerifySignature(profile, envPart, signature, identity.identityKey);
            Envelope.JSONData parameters = JsonSerializer.Deserialize<Envelope.JSONData>(Utility.FromBase64(components[3]));
            Envelope envelope = new Envelope(identity, parameters, profile);
            byte[] msgBytes = Utility.FromBase64(components[2]);
            string[] msgArray = System.Text.Encoding.UTF8.GetString(msgBytes, 0, msgBytes.Length).Split(new char[] { ';' }); ;
            foreach(string msg in msgArray)
            {
                Message message = Message.Import(msg);
                envelope.AddMessage(message);
            }
            envelope.encoded = envPart;
            envelope.signature = signature;
            envelope.isImmutable = true;
            return envelope;
        }

        public string Export(string identityPrivateKey = null)
        {
            if (this.signature == null && identityPrivateKey == null) { throw new ArgumentNullException("Need private key to sign envelope for export."); }
            if (this.signature == null)
            {
                this.encoded = Encode(identityPrivateKey);
                this.signature = Crypto.GenerateSignature(this.profile, this.encoded, identityPrivateKey);
                this.isImmutable = true;
            }
            Crypto.VerifySignature(this.profile, this.encoded, this.signature, this.identity.identityKey);
            return this.encoded + "." + this.signature;
        }

        public void AddMessage(Message message)
        {
            if (!this.isImmutable)
            {
                if (this.messages == null)
                {
                    this.messages = new List<Message>();
                }
                this.messages.Add(message);
            }
            else
            {
                throw new ImmutableException();
            }
        }

        /* PRIVATE */
        private const string HEADER = "E";
        private string signature;
        private string encoded;
        private struct JSONData
        {
            public Guid uid { get; set; }
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }

            public JSONData(Guid uid, Guid sub, Guid iss, long iat, long exp)
            {
                this.uid = uid;
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
            }
        }
        private Envelope.JSONData json;

        private Envelope(Identity issuerIdentity, Envelope.JSONData parameters, int profile = Crypto.DEFUALT_PROFILE)
        {
            this.identity = issuerIdentity;
            this.json = parameters;
            this.profile = profile;
        }

        private string Encode(string issuerIdentityPrivateKey = null)
        {
            if ( this.encoded == null ) 
            {  
                var envBuilder = new StringBuilder();
                envBuilder.AppendFormat("{0}{1}.{2}.", 
                                    Envelope.HEADER,
                                    this.profile,
                                    Utility.ToBase64(this.identity.Export()));
                var msgBuilder = new StringBuilder();
                foreach (Message message in this.messages)
                {
                    string msg = message.HasSignature() ? message.Export() : message.Export(issuerIdentityPrivateKey);
                    msgBuilder.AppendFormat("{0};", msg);
                }
                msgBuilder.Remove(msgBuilder.Length - 1, 1); 
                envBuilder.AppendFormat("{0}.{1}",
                                        Utility.ToBase64(msgBuilder.ToString()),
                                        Utility.ToBase64(JsonSerializer.Serialize(this.json)));
                this.encoded = envBuilder.ToString();
            }
            return this.encoded;
        }

    }

}
