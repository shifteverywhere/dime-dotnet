//
//  Message.cs
//  DiME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
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
    public class Message: Dime, IAttached
    {
        #region -- PUBLIC --

        public const string ITID = "aW8uZGltZWZvcm1hdC5tc2c"; // base64 of io.dimeformat.msg

        /// <summary>A unique identity for the message.</summary>
        public override Guid Id { get { return this._claims.uid; } }
        /// <summary>The id of the receiver.</summary>
        public Guid AudienceId { get { return this._claims.aud; } }
        /// <summary>The id of the issuer (subject id of the issuer).</summary>
        public Guid IssuerId { get { return this._claims.iss; } }
        /// <summary>The timestamp of when the message was created (issued).</summary>
        public long IssuedAt { get { return this._claims.iat; } }
        /// <summary>The timestamp of when the message is expired and is no longer valid.</summary>
        public long ExpiresAt { get { return this._claims.exp ?? -1; } }
        /// <summary>A link to another message. Used when responding to anther message.</summary>
        public string LinkedTo { get { return this._claims.lnk; } }
        public Identity Issuer { get; private set; }

        public bool IsSealed { get { return (this._signature != null); } }

        public Message() { }

        public Message(Identity audience, Identity issuer, long? validFor = null)
        {
            if (audience == null) { throw new ArgumentNullException(nameof(audience), "Audience (receiver) identity must not be null."); }
            if (issuer == null) { throw new ArgumentNullException(nameof(issuer), "Issuer (sender) identity must not be null."); }
            long iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long? exp = (validFor.HasValue && validFor.Value > 0) ? iat + validFor.Value : null; 
            this.Issuer = issuer;
            this._claims = new MessageClaims(Guid.NewGuid(), audience.SubjectId, issuer.SubjectId, iat, exp, null, null, null);
            this.Profile = issuer.Profile;
        }

        public Message Seal(string privateKey)
        {
            if (this._signature == null)
            {
                if (privateKey == null) { throw new ArgumentNullException(nameof(privateKey), "Private key for signing cannot be null."); }
                if (this._payload == null) { throw new DataFormatException("Unable to seal message, no payload added."); }
                this._signature = Crypto.GenerateSignature(this.Issuer.Profile, Encoded(), privateKey);
            }
            return this;
        }

        public void Verify(Message linkedMessage = null) { 
            if (!Crypto.SupportedProfile(this.Profile)) { throw new UnsupportedProfileException("Unsupported cryptography profile version."); }
            if (this._payload == null || this._payload.Length == 0) { throw new DataFormatException("Missing payload in message."); }
            // Verify IssuedAt and ExpiresAt
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (this.IssuedAt > now) { throw new DateExpirationException("Issuing date in the future."); }
            if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Expiration before issuing date."); }
            if (this.ExpiresAt < now) { throw new DateExpirationException("Passed expiration date."); }
            if (linkedMessage != null)
            {
                if (this._claims.lnk == null || this._claims.lnk.Length == 0) { throw new DataFormatException("No linked message found, unable to verify."); }
                string[] components = this._claims.lnk.Split(new char[] { ':' });
                if (components == null || components.Length != 2) { throw new DataFormatException("Invalid data found in message link field."); }
                string msgHash = linkedMessage.Thumbprint();
                if (components[0] != linkedMessage.Id.ToString() || components[1] != msgHash) { throw new IntegrityException("Failed to verify message link (provided message did not match)."); }
            }
            // TODO: validate issuer
            Crypto.VerifySignature(this.Issuer.Profile, Encoded(), this._signature, this.Issuer.IdentityKey);
         }

        /// <summary>Will set a message payload. This may be any valid byte-array, at export this will be
        /// encoded as a Base64 string. If a payload is already set, then the old will be overwritten.</summary>
        /// <param name="payload">The payload to set.</param>
        public void SetPayload(byte[] payload)
        {
            if (this.IsSealed) { throw new IntegrityException("Message already sealed."); }
            this._payload = Utility.ToBase64(payload);
        }

        /// <summary>Returns the payload inside the message.</summary>
        /// <returns>A byte-array.</returns>
        public byte[] GetPayload()
        {
            return Utility.FromBase64(this._payload);
        }

        /// <summary>This will link a message to this message. Used most often when responding to another message.
        /// The original message is then linked to the response message. This will cryptographically link the two
        /// messages together.</summary>
        /// <param name="message">The message object to link to.</param>
        /// <exception cref="ArgumentNullException">If the passed message object is null.</exception> 
        public void LinkMessage(Message message)
        {
            if (message == null) { throw new ArgumentNullException(nameof(message), "Message to link must not be null."); }
            if (this.IsSealed) { throw new IntegrityException("Message already sealed."); }
            this._claims.lnk = $"{message.Id.ToString()}:{message.Thumbprint()}";
        }

        #endregion

        #region -- INTERNAL --

        internal override void Populate(Identity issuer, string encoded)
        {
            this.Issuer = issuer;
            this.Profile = this.Issuer.Profile;
            string[] components = encoded.Split(new char[] { Dime._COMPONENT_DELIMITER });
            if (components.Length != Message._NBR_EXPECTED_COMPONENTS) { throw new DataFormatException($"Unexpected number of components for identity issuing request, expected {Message._NBR_EXPECTED_COMPONENTS}, got {components.Length}."); }
            if (components[Message._IDENTIFIER_INDEX] != Message.ITID) { throw new DataFormatException($"Unexpected object identifier, expected: \"{Message.ITID}\", got \"{components[Message._IDENTIFIER_INDEX]}\"."); }
            this._claims = JsonSerializer.Deserialize<MessageClaims>(Utility.FromBase64(components[Message._CLAIMS_INDEX]));
            this._payload = components[Message._PAYLOAD_INDEX];
        }

        internal override string Encoded(bool includeSignature = false)
        {
            if (this._encoded == null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(this.Issuer.Encoded(true));
                builder.Append(Dime._SECTION_DELIMITER);
                builder.Append(Message.ITID);
                builder.Append(Dime._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                builder.Append(Dime._COMPONENT_DELIMITER);
                builder.Append(this._payload);
                this._encoded = builder.ToString();
            }
            if (includeSignature && !this.IsSealed) { throw new IntegrityException("Message is not sealed, cannot be exported."); }
            return (includeSignature) ? $"{this._encoded}{Dime._COMPONENT_DELIMITER}{this._signature}" : this._encoded;
        }        

        #endregion

        # region -- PROTECTED --
        
        protected override void FixateEncoded(string encoded)
        {
            this._encoded = encoded.Substring(0, encoded.LastIndexOf(Dime._COMPONENT_DELIMITER));
            this._signature = encoded.Substring(encoded.LastIndexOf(Dime._COMPONENT_DELIMITER) + 1);
        }

        #endregion

        #region -- PRIVATE --

        private const int _NBR_EXPECTED_COMPONENTS = 4;
        private const int _IDENTIFIER_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;
        private const int _PAYLOAD_INDEX = 2;
        private MessageClaims _claims;
        private string _encoded;
        private string _signature;
        private string _payload;

        private struct MessageClaims
        {
            public Guid uid { get; set; }
            public Guid aud { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public long? exp { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public Guid? kid { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string xky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string lnk { get; set; }

            [JsonConstructor]
            public MessageClaims(Guid uid, Guid aud, Guid iss, long iat, long? exp, Guid? kid, string xky, string lnk)
            {
                this.uid = uid;
                this.aud = aud;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
                this.kid = kid;
                this.xky = xky;
                this.lnk = lnk;
            }
        }

        #endregion

    }

}
