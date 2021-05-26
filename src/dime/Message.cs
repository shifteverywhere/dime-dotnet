using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    /// <summary></summary>
    public class Message
    {
        #region -- PUBLIC --
        /// <summary></summary>
        public int Profile { get { return this._profile; } set { Reset(); this._profile = value; } }
        /// <summary></summary>
        public Identity Identity { get { return this._identity; } set { Reset(); this._identity = value; } }
        /// <summary></summary>
        public byte[] State { get { return this._state != null ? Utility.FromBase64(this._state) : null; } set { Reset(); this._state = value != null ? Utility.ToBase64(value) : null; } }
        /// <summary>A unique identity for the message. If a message is modfied after it has been sealed, then this id changes.</summary>
        public Guid Id { get { return this._data.uid; } }
        /// <summary></summary>
        public Guid SubjectId { get { return this._data.sub; } set { Reset(); this._data.sub = value; } }
        /// <summary></summary>
        public Guid IssuerId { get { return this._data.iss; } set { Reset(); this._data.iss = value; } }
        /// <summary></summary>
        public long IssuedAt { get { return this._data.iat; } set { Reset(); this._data.iat = value; } }
        /// <summary></summary>
        public long ExpiresAt { get { return this._data.exp; } set { Reset(); this._data.exp = value; } }
        /// <summary></summary>
        public string ExchangeKey { get { return this._data.xky; } set { Reset(); this._data.xky = value; } }
        /// <summary></summary>
        public string LinkedTo { get { return this._data.lnk; } set { Reset(); this._data.lnk = value; } }
        /// <summary></summary>
        public bool IsSealed { get { return this._signature != null; } }
        /// <summary>const string to improve performance</summary>
        public const string delimiter = ".";

        /// <summary></summary>
        public Message(Guid subjectId, Identity issuerIdentity, long validFor)
        {
            if (issuerIdentity == null) { throw new ArgumentNullException("issuerIdentity cannot be null"); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            this.Profile = issuerIdentity.Profile;
            this.Identity = issuerIdentity;
            this._data = new Message.InternalData(Guid.NewGuid(), subjectId, issuerIdentity.SubjectId, now, (now + validFor));
        }

        /// <summary></summary>
        public static Message Import(string encoded, Message linkedMessage = null)
        {
            if (!encoded.StartsWith(Message._HEADER)) { throw new ArgumentException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { '.' });
            if (components.Length != 5 && components.Length != 6) { throw new ArgumentException("Unexpected number of components found when decoding identity."); }
            int profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] identityBytes = Utility.FromBase64(components[1]);
            Identity identity = Identity.Import(System.Text.Encoding.UTF8.GetString(identityBytes, 0, identityBytes.Length));
            Message.InternalData parameters = JsonSerializer.Deserialize<Message.InternalData>(Utility.FromBase64(components[2]));
            Message message = new Message(identity, parameters, profile);
            message._payload = components[3];
            if(components.Length == 6)
            {
                message._state = components[4];
            }
            message._encoded = encoded.Substring(0, encoded.LastIndexOf('.'));
            message._signature = components[components.Length - 1];
            message.Verify(linkedMessage != null ? linkedMessage.Export() : null);
            return message;
        }

        public string Export()
        {
            if (!this.IsSealed) { throw new IntegrityException("Signature missing, unable to export."); }
            
            Verify();

            StringBuilder sb = new StringBuilder();
            sb.Append(Encode());
            sb.Append(delimiter);
            sb.Append(_signature);

            return sb.ToString();
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="linkedMessage"></param>
        public void Verify(string linkedMessage = null)
        {
            if (!Crypto.SupportedProfile(this.Profile)) { throw new UnsupportedProfileException("Unsupported cryptography profile version."); }
            // Verify IssuedAt and ExpiresAt
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (this.IssuedAt > now) { throw new DateExpirationException("Issuing date in the future."); }
            if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Expiration before issuing date."); }
            if (this.ExpiresAt < now) { throw new DateExpirationException("Passed expiration date."); }
            // Verify identity
            this.Identity.VerifyTrust();
            // Verify linkedMessage
            if (this._data.lnk != null && linkedMessage != null)
            {
                string msgHash = Crypto.GenerateHash(this.Profile, linkedMessage);
                if (msgHash != this._data.lnk) { throw new IntegrityException("Linked message mismatch."); }
            }
            // Verify signature
            if (this._signature == null) { throw new IntegrityException("Signature missing."); }
            if (this.Identity.SubjectId != this.IssuerId) { throw new IntegrityException("Issuing identity subject id does not match issuer id of the message."); }
            Crypto.VerifySignature(this.Profile, Encode(), this._signature, this.Identity.IdentityKey);
        }

        public void Seal(string identityPrivateKey)
        {
            if (!this.IsSealed)
            {
                if (identityPrivateKey == null) { throw new ArgumentNullException("Private key for signing cannot be null."); }
                this._signature = Crypto.GenerateSignature(this.Profile, Encode(), identityPrivateKey);
            }
        }

        public static bool IsMessage(string encoded)
        {
            return encoded.StartsWith(Message._HEADER);
        }

        public void AddPayload(byte[] payload)
        {
            Reset();
            // TODO: E2EE
            this._payload = Utility.ToBase64(payload);
        }

        public byte[] GetPayload()
        {
            // TODO: E2EE
            return Utility.FromBase64(this._payload);
        }

        public void LinkMessage(Message message)
        {
            Reset();
            if (message == null) { throw new ArgumentNullException("Message to link must not be null."); }
            this._data.lnk = Crypto.GenerateHash(this.Profile, message.Export());
        }
        #endregion

        #region -- PRIVATE --
        private const string _HEADER = "M";
        private int _profile;
        private Identity _identity;
        private string _state;
        private string _payload;
        private string _signature;
        private string _encoded;
        private struct InternalData
        {
            public Guid uid { get; set; }
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string xky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string lnk { get; set; }

            public InternalData(Guid uid, Guid sub, Guid iss, long iat, long exp, string xky = null, string lnk = null)
            {
                this.uid = uid;
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
                this.xky = xky;
                this.lnk = lnk;
            }
        }
        private Message.InternalData _data;

        private Message(Identity issuerIdentity, Message.InternalData parameters, int profile = Crypto.DEFUALT_PROFILE)
        {
            if (issuerIdentity == null) { throw new ArgumentNullException("issuerIdentity cannot be null"); }
            this.Identity = issuerIdentity;
            this.Identity = issuerIdentity;
            this._data = parameters;
            this.Profile = profile;
        }

        private string Encode()
        {
            if ( this._encoded == null ) 
            {  
                // TODO: verify all values (payload == null ??)
                var builder = new StringBuilder(); 
                builder.AppendFormat("{0}{1}.{2}.{3}", 
                                    Message._HEADER,
                                    this.Profile,
                                    Utility.ToBase64(this.Identity.Export()),
                                    Utility.ToBase64(JsonSerializer.Serialize(this._data)));
                builder.AppendFormat(".{0}", this._payload);
                if ( this.State != null)
                {
                    builder.AppendFormat(".{0}", this._state);
                }
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        private void Reset()
        {
            this._data.uid = Guid.NewGuid();
            this._encoded = null;
            this._signature = null;
        }
        #endregion

    }

}
