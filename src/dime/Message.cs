using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    ///<summary>Holds a message from one subject (issuer) to another. The actual message is held as a byte[] and may be
    /// optionally encrypted (using end-to-end encryption). Responses to messages may be linked with the orginal message, thus
    /// creating a strong cryptographical link. The entity that created the message signs it before exporting and thus sealing
    /// it's content. </summary>
    public class Message
    {
        #region -- PUBLIC --
        /// <summary>The cryptographic profile version used for this envelope.</summary>
        public int Profile { get { return this._profile; } set { Reset(); this._profile = value; } }
        /// <summary>The identity of the issuer, and thus sealer (signer), of the message.</summary>
        public Identity Identity { get { return this._identity; } set { Reset(); this._identity = value; } }
        /// <summary>The state property may be used by an issuer to store data that should be returned back
        /// to the issuer unmodified. This allows for stateless message sending.</summary>
        public byte[] State { get { return this._state != null ? Utility.FromBase64(this._state) : null; } set { Reset(); this._state = value != null ? Utility.ToBase64(value) : null; } }
        /// <summary>A unique identity for the message. If a message is modfied after it has been sealed, then this id changes.</summary>
        public Guid Id { get { return this._data.uid; } }
        /// <summary>The id of the receiver.</summary>
        public Guid SubjectId { get { return this._data.sub; } set { Reset(); this._data.sub = value; } }
        /// <summary>The id of the issuer (subject id of the issuer).</summary>
        public Guid IssuerId { get { return this._data.iss; } set { Reset(); this._data.iss = value; } }
        /// <summary>The timestamp of when the message was created (issued).</summary>
        public long IssuedAt { get { return this._data.iat; } set { Reset(); this._data.iat = value; } }
        /// <summary>The timestamp of when the message is expired and is no longer valid.</summary>
        public long ExpiresAt { get { return this._data.exp; } set { Reset(); this._data.exp = value; } }
        /// <summary>!NOT IMPLEMENTED!</summary>
        public string ExchangeKey { get { return this._data.xky; } set { Reset(); this._data.xky = value; } }
        /// <summary>A link to another message. Used when responding to anther message.</summary>
        public string LinkedTo { get { return this._data.lnk; } set { Reset(); this._data.lnk = value; } }
        /// <summary>Indicates if the envelope is sealed or not (signed).</summary>
        public bool IsSealed { get { return this._signature != null; } }

        /// <summary>Creates a new message. The message will be valid from the time of creation until
        /// the seconds set in 'validFor' have passed.</summary>
        /// <param name="subjectId">The id of the receiver of the message.</param>
        /// <param name="issuerIdentity">The identity of the sender of the message.</param>
        /// <param name="validFor">The number of seconds before the message expires.</param>
        /// <exception cref="ArgumentNullException">If issuer identity is null.</exception>
        public Message(Guid subjectId, Identity issuerIdentity, long validFor)
        {
            if (issuerIdentity == null) { throw new ArgumentNullException(nameof(issuerIdentity), "Issuing identity cannot be null"); }
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            this._profile = issuerIdentity.Profile;
            this._identity = issuerIdentity;
            this._data = new Message.InternalData(Guid.NewGuid(), subjectId, issuerIdentity.SubjectId, now, (now + validFor));
        }

        /// <summary>Creates a message object from a DiME encoded string. It will also verify field values and
        /// signatures before returning a new instance. If a linked message object is passed, then the 'LinkedTo'
        /// will also be validated.</summary>
        /// <param name="encoded">The DiME encoded envelope string to import.</param>
        /// <param name="linkedMessage">A linked message that should be considered when verifying (optional).</param>
        /// <exception cref="DataFormatException">If the format of the encoded string is invalid.</exception>
        /// <exception cref="UnsupportedProfileException">If an invalid cryptographic profile version is set.</exception>
        /// <exception cref="DateExpirationException">If 'IssuedAt' and/or 'ExpiresAt' contain invalid values, or the message has expired.</exception>
        /// <exception cref="IntegrityException">If the signature failes validation, or cannot be validated.</exception>
        /// <returns>An initialized and verified Message object.</returns>
        public static Message Import(string encoded)
        {
            if (!encoded.StartsWith(Message._HEADER)) { throw new DataFormatException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { Message._MAIN_DELIMITER });
            if (components.Length != 5 && components.Length != 6) { throw new DataFormatException("Unexpected number of components found when decoding identity."); }
            int profile = int.Parse(components[0].Substring(1));
            if (!Crypto.SupportedProfile(profile)) { throw new UnsupportedProfileException("Unsupported cryptography profile."); }
            byte[] identityBytes = Utility.FromBase64(components[1]);
            Identity identity = Identity.Import(System.Text.Encoding.UTF8.GetString(identityBytes, 0, identityBytes.Length));
            Message.InternalData parameters = JsonSerializer.Deserialize<Message.InternalData>(Utility.FromBase64(components[2]));
            Message message = new Message(identity, parameters, profile);
            message._payload = components[3];
            if(components.Length == 6)
            {
                message._state = components[4];
            }
            message._encoded = encoded.Substring(0, encoded.LastIndexOf(Message._MAIN_DELIMITER));
            message._signature = components[components.Length - 1];
            return message;
        }

        /// <summary>This function encodes and exports the message object in the DiME format. It will verify 
        /// the data inside the message, as well as the signature attached.</summary>
        /// <exception cref="IntegrityException">If the signature failes validation, or cannot be validated.</exception>
        /// <returns>A DiME encoded string.</returns>
        public string Export()
        {
            if (!this.IsSealed) { throw new IntegrityException("Signature missing, unable to export."); }
            StringBuilder sb = new StringBuilder();
            sb.Append(Encode());
            sb.Append(Message._MAIN_DELIMITER);
            sb.Append(this._signature);
            return sb.ToString();
        }

        /// <summary>Will verify the data in the fields in the message object. If a message is passed, then it will
        /// also verify the 'LinkedTo' field. The signature of the message object will be verified with the public key from 
        /// the 'Identity.TrustedIdentity' property.</summary>
        /// <param name="linkedMessage">A linked message that should be considred during verification.</param>
        /// <exception cref="UnsupportedProfileException">If an invalid cryptographic profile version is set.</exception>
        /// <exception cref="DataFormatException">If no payload has been set in the message, or linked message value is invalid.</exception>
        /// <exception cref="DateExpirationException">If 'IssuedAt' and/or 'ExpiresAt' contain invalid values, or the message has expired.</exception>
        /// <exception cref="IntegrityException">If the signature failes validation, or cannot be validated.</exception>
        public void Verify(Message linkedMessage = null)
        {
            if (!Crypto.SupportedProfile(this.Profile)) { throw new UnsupportedProfileException("Unsupported cryptography profile version."); }
            if (this._payload == null || this._payload.Length == 0) { throw new DataFormatException("Missing payload in message."); }
            // Verify IssuedAt and ExpiresAt
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (this.IssuedAt > now) { throw new DateExpirationException("Issuing date in the future."); }
            if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Expiration before issuing date."); }
            if (this.ExpiresAt < now) { throw new DateExpirationException("Passed expiration date."); }
            // Verify identity
            this.Identity.Verify();
            // Verify linkedMessage
            if (this._data.lnk != null && linkedMessage != null)
            {
                string[] components = this._data.lnk.Split(new char[] { ':' });
                if (components == null || components.Length != 2) { throw new DataFormatException("Invalid message link."); }
                string msgHash = linkedMessage.Thumbprint();
                if (components[0] != linkedMessage.Id.ToString() || components[1] != msgHash) { throw new IntegrityException("Linked message mismatch."); }
            }
            // Verify signature
            if (this._signature == null) { throw new IntegrityException("Signature missing."); }
            if (this.Identity.SubjectId != this.IssuerId) { throw new IntegrityException("Issuing identity subject id does not match issuer id of the message."); }
            Crypto.VerifySignature(this.Profile, Encode(), this._signature, this.Identity.IdentityKey);
        }

        /// <summary>This will seal a message by signing it using the provided private key (of key type 'Identity').
        /// The provided private key must be associated with the public key in the 'Idenity' object inside the message
        /// object to be signed. If not, then the message will not be trusted by the receiving party.</summary>
        /// <param name="identityPrivateKey">The private key that should be used to sign the message.</param>
        /// <exception cref="ArgumentNullException">If the passed private key is null.</exception> 
        /// <exception cref="ArgumentException">If required data is missing in the envelope.</exception> 
        /// <exception cref="UnsupportedProfileException">If an invalid cryptographic profile version is set.</exception>
        /// <exception cref="DataFormatException">If no payload has been set in the message.</exception>
        /// <exception cref="DateExpirationException">If 'IssuedAt' and/or 'ExpiresAt' contain invalid values, or the message has expired.</exception>
        public void Seal(string identityPrivateKey)
        {
            if (!this.IsSealed)
            {
                if (identityPrivateKey == null) { throw new ArgumentNullException(nameof(identityPrivateKey), "Private key for signing cannot be null."); }
                this._signature = Crypto.GenerateSignature(this.Profile, Encode(), identityPrivateKey);
                Verify();
            }
        }

        /// <summary>Helper function to quickly check if a string is potentially a DiME encoded message object.</summary>
        /// <param name="encoded">The string to validate.</param>
        /// <returns>An indication if the string is a DiME encoded message.</returns>
        public static bool IsMessage(string encoded)
        {
            return encoded.StartsWith(Message._HEADER);
        }

        /// <summary>Will set a message payload. This may be any valid byte-array, at export this will be
        /// encoded as a Base64 string. If a payload is already set, then the old will be overwritten.</summary>
        /// <param name="payload">The payload to set.</param>
        public void SetPayload(byte[] payload)
        {
            Reset();
            // TODO: E2EE
            this._payload = Utility.ToBase64(payload);
        }

        /// <summary>Returns the payload inside the message.</summary>
        /// <returns>A byte-array.</returns>
        public byte[] GetPayload()
        {
            // TODO: E2EE
            return Utility.FromBase64(this._payload);
        }

        /// <summary>This will link a message to this message. Used most often when responding to another message.
        /// The original message is then linked to the response message. This will cryptographically link the two
        /// messages together.</summary>
        /// <param name="message">The message object to link to.</param>
        /// <exception cref="ArgumentNullException">If the passed message object is null.</exception> 
        public void LinkMessage(Message message)
        {
            Reset();
            if (message == null) { throw new ArgumentNullException(nameof(message), "Message to link must not be null."); }
            this._data.lnk = string.Format("{0}:{1}",
                                           message.Id.ToString(),
                                           message.Thumbprint());
        }

        /// <summary>Generates a cryptographically unique thumbprint of the message.</summary>
        /// <exception cref="IntegrityException">If message is not sealed (signed).</exception> 
        /// <returns>An unique thumbprint.</returns>
        public string Thumbprint() 
        {
            if(!this.IsSealed) { throw new IntegrityException("Message not sealed."); }
            return Crypto.GenerateHash(this.Profile, Encode());
        }
        #endregion

        #region -- PRIVATE --
        private const string _HEADER = "M";
        private const char _MAIN_DELIMITER = '.';
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

            [JsonConstructor]
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
            this._identity = issuerIdentity;
            this._data = parameters;
            this._profile = profile;
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
            if (this.IsSealed)
            {
                this._data.uid = Guid.NewGuid();
                this._encoded = null;
                this._signature = null;
            }
        }
        #endregion

    }

}
