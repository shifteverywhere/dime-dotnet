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
    public class Message: Dime
    {
        #region -- PUBLIC --
        /// <summary>The cryptographic profile version used for this envelope.</summary>
        public new ProfileVersion Profile { get { return base.Profile; } set { Reset(); base.Profile = value; } }
        /// <summary>The identity of the issuer, and thus sealer (signer), of the message.</summary>
        public Identity Identity { get { return this._identity; } set { Reset(); this._identity = value; } }
        /// <summary>The state property may be used by an issuer to store data that should be returned back
        /// to the issuer unmodified. This allows for stateless message sending.</summary>
        public byte[] State { get { return this._state != null ? Utility.FromBase64(this._state) : null; } set { Reset(); this._state = value != null ? Utility.ToBase64(value) : null; } }
        /// <summary>A unique identity for the message. If a message is modfied after it has been sealed, then this id changes.</summary>
        public Guid Id { get { return this._claims.uid; } }
        /// <summary>The id of the receiver.</summary>
        public Guid SubjectId { get { return this._claims.sub; } set { Reset(); this._claims.sub = value; } }
        /// <summary>The id of the issuer (subject id of the issuer).</summary>
        public Guid IssuerId { get { return this._claims.iss; } set { Reset(); this._claims.iss = value; } }
        /// <summary>The timestamp of when the message was created (issued).</summary>
        public long IssuedAt { get { return this._claims.iat; } set { Reset(); this._claims.iat = value; } }
        /// <summary>The timestamp of when the message is expired and is no longer valid.</summary>
        public long ExpiresAt { get { return this._claims.exp; } set { Reset(); this._claims.exp = value; } }
        /// <summary>!NOT IMPLEMENTED! (E2EE)</summary>
        public Guid? KeyId { get { return this._claims.kid; } }
        /// <summary>!NOT IMPLEMENTED! (E2EE)</summary>
        public string ExchangeKey { get { return this._claims.xky; } }
        /// <summary>A link to another message. Used when responding to anther message.</summary>
        public string LinkedTo { get { return this._claims.lnk; } set { Reset(); this._claims.lnk = value; } }

        public Message() { }

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
            this.Profile = issuerIdentity.Profile;
            this._identity = issuerIdentity;
            this._claims = new MessageClaims(Guid.NewGuid(), subjectId, issuerIdentity.SubjectId, now, (now + validFor), null, null, null);
        }

        public override void Seal(string privateKey)
        {
            if (this._payload == null) { throw new DataFormatException("No payload added to message."); } 
            base.Seal(privateKey);
        }

        public override void Verify() { 
            if (!Crypto.SupportedProfile(this.Profile)) { throw new UnsupportedProfileException("Unsupported cryptography profile version."); }
            if (this._payload == null || this._payload.Length == 0) { throw new DataFormatException("Missing payload in message."); }
            // Verify IssuedAt and ExpiresAt
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (this.IssuedAt > now) { throw new DateExpirationException("Issuing date in the future."); }
            if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Expiration before issuing date."); }
            if (this.ExpiresAt < now) { throw new DateExpirationException("Passed expiration date."); }
            // Verify identity
            this.Identity.Verify();
            // Verify signature
            if (this._signature == null) { throw new IntegrityException("Signature missing."); }
            if (this.Identity.SubjectId != this.IssuerId) { throw new IntegrityException("Issuing identity subject id does not match issuer id of the message."); }
            Crypto.VerifySignature(this.Profile, Encode(), this._signature, this.Identity.IdentityKey);
         }

        /// <summary>Will verify the data in the fields in the message object. If a message is passed, then it will
        /// also verify the 'LinkedTo' field. The signature of the message object will be verified with the public key from 
        /// the 'Identity.TrustedIdentity' property.</summary>
        /// <param name="linkedMessage">A linked message that should be considred during verification.</param>
        /// <exception cref="UnsupportedProfileException">If an invalid cryptographic profile version is set.</exception>
        /// <exception cref="DataFormatException">If no payload has been set in the message, or linked message value is invalid.</exception>
        /// <exception cref="DateExpirationException">If 'IssuedAt' and/or 'ExpiresAt' contain invalid values, or the message has expired.</exception>
        /// <exception cref="IntegrityException">If the signature failes validation, or cannot be validated.</exception>
        public void Verify(Message linkedMessage)
        {
            if (linkedMessage == null) { throw new ArgumentNullException(nameof(linkedMessage), "Message to veryfi with must not be null."); }
            if (this._claims.lnk == null || this._claims.lnk.Length == 0) { throw new DataFormatException("No linked message found, unable to verify."); }
            Verify();
            string[] components = this._claims.lnk.Split(new char[] { ':' });
            if (components == null || components.Length != 2) { throw new DataFormatException("Invalid data found in message link field."); }
            string msgHash = linkedMessage.Thumbprint();
            if (components[0] != linkedMessage.Id.ToString() || components[1] != msgHash) { throw new IntegrityException("Failed to verify message link (provided message did not match)."); }
        }

        /// <summary>Will set a message payload. This may be any valid byte-array, at export this will be
        /// encoded as a Base64 string. If a payload is already set, then the old will be overwritten.</summary>
        /// <param name="payload">The payload to set.</param>
        public void SetPayload(byte[] payload)
        {
            Reset();
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
            Reset();
            if (message == null) { throw new ArgumentNullException(nameof(message), "Message to link must not be null."); }
            this._claims.lnk = string.Format("{0}:{1}",
                                           message.Id.ToString(),
                                           message.Thumbprint());
        }

        #endregion

        #region -- PROTECTED --

        protected override void Populate(string encoded)
        {
            if (Dime.GetType(encoded) != typeof(Message)) { throw new DataFormatException("Invalid header."); }
            string[] components = encoded.Split(new char[] { Dime._COMPONENT_DELIMITER });
            if (components.Length != 5 && components.Length != 6) { throw new DataFormatException("Unexpected number of components found when decoding identity."); }
            ProfileVersion profile;
            Enum.TryParse<ProfileVersion>(components[0].Substring(1), true, out profile);
            this.Profile = profile;
            if (!Crypto.SupportedProfile(this.Profile)) { throw new UnsupportedProfileException("Unsupported cryptography profile."); }
            byte[] identityBytes = Utility.FromBase64(components[1]);
            this.Identity = Dime.Import<Identity>(System.Text.Encoding.UTF8.GetString(identityBytes, 0, identityBytes.Length));
            this._claims = JsonSerializer.Deserialize<MessageClaims>(Utility.FromBase64(components[2]));
            this._payload = components[3];
            if(components.Length == 6)
            {
                this._state = components[4];
            }
            this._encoded = encoded.Substring(0, encoded.LastIndexOf(Message._COMPONENT_DELIMITER));
            this._signature = components[components.Length - 1];
        }

        protected override string Encode()
        {
            if ( this._encoded == null ) 
            {  
                StringBuilder builder = new StringBuilder(); 
                builder.Append('M'); // The header of an DiME message
                builder.Append((int)this.Profile);
                builder.Append(Dime._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(this.Identity.Export()));
                builder.Append(Dime._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                builder.Append(Dime._COMPONENT_DELIMITER);
                builder.Append(this._payload);
                if ( this.State != null)
                {
                    builder.Append(Dime._COMPONENT_DELIMITER);
                    builder.Append(this._state);
                }
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }        

        #endregion

        #region -- PRIVATE --

        private struct MessageClaims
        {
            public Guid uid { get; set; }
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }
             [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public Guid? kid { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string xky { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string lnk { get; set; }

            [JsonConstructor]
            public MessageClaims(Guid uid, Guid sub, Guid iss, long iat, long exp, Guid? kid, string xky, string lnk)
            {
                this.uid = uid;
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
                this.kid = kid;
                this.xky = xky;
                this.lnk = lnk;
            }
        }
        private MessageClaims _claims;
        private Identity _identity;
        private string _state;
        private string _payload;

        private void Reset()
        {
            if (this.IsSealed)
            {
                this._claims.uid = Guid.NewGuid();
                this._encoded = null;
                this._signature = null;
            }
        }

        #endregion

    }

}
