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

        public Envelope(Identity issuerIdentity, Guid subjectId, long issuedAt, long expiresAt, int profile = Crypto.DEFUALT_PROFILE)
        {
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            this.identity = issuerIdentity;
            this.json = new JSONData(subjectId, issuerIdentity.subjectId, issuedAt, expiresAt);
            this.profile = profile;
        }

        public static Envelope Import(string encoded)
        {
            if (!encoded.StartsWith(Envelope.HEADER)) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(".");
            if (components.Length != 5) { throw new ArgumentException("Unexpected number of components found then decoding identity."); }
            int profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] identityBytes = Utility.FromBase64(components[1]);
            Identity identity = Identity.Import(System.Text.Encoding.UTF8.GetString(identityBytes, 0, identityBytes.Length));
            if (identity.VerifyTrust())
            {
                string envPart = encoded.Substring(0, encoded.LastIndexOf('.'));
                string signature = components[components.Length - 1];
                if (!Crypto.VerifySignature(profile, envPart, signature, identity.identityKey))
                {
                    throw new ArgumentException("Unable to verify message signature."); // TODO: throw more specific exception
                }
                Envelope.JSONData parameters = JsonSerializer.Deserialize<Envelope.JSONData>(Utility.FromBase64(components[3]));
                Envelope envelope = new Envelope(identity, parameters, profile);
                byte[] msgBytes = Utility.FromBase64(components[2]);
                string[] msgArray = System.Text.Encoding.UTF8.GetString(msgBytes, 0, msgBytes.Length).Split(";");
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
            throw new ArgumentNullException("Untrusted identity."); // TODO: throw more specific exception            
        }

        public string Export(string identityPrivateKey)
        {
            if (this.signature == null)
            {
                this.signature = Crypto.GenerateSignature(this.profile, Encode(), identityPrivateKey);
            }
            return Encode() + "." + this.signature;
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
                throw new ArgumentNullException("This envelope object is imutable."); // TODO: throw another exception
            }
        }

        /* PRIVATE */
        private const string HEADER = "E";
        private string signature;
        private bool isImmutable = false;
        private string encoded;
        private struct JSONData
        {
            public Guid sub;
            public Guid iss;
            public long iat;
            public long exp;

            public JSONData(Guid sub, Guid iss, long iat, long exp)
            {
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

        private string Encode()
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
                    msgBuilder.AppendFormat("{0};", message.Export());
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
