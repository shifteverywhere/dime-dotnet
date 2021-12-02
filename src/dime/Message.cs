//
//  Message.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;

namespace ShiftEverywhere.DiME
{
    ///<summary>Holds a message from one subject (issuer) to another. The actual message is held as a byte[] and may be
    /// optionally encrypted (using end-to-end encryption). Responses to messages may be linked with the orginal message, thus
    /// creating a strong cryptographical link. The entity that created the message signs it before exporting and thus sealing
    /// it's content. </summary>
    public class Message: Item
    {
        #region -- PUBLIC DATA MEMBERS --
        public const string TAG = "MSG"; 
        public override string Tag { get { return Message.TAG; } }
        /// <summary>A unique identifier for the message.</summary>
        public override Guid UniqueId { get { return this._claims.uid; } }
        /// <summary>The id of the receiver.</summary>
        public Guid? AudienceId { get { return this._claims.aud; } }
        /// <summary>The id of the issuer (subject id of the issuer).</summary>
        public Guid IssuerId { get { return this._claims.iss; } }
        /// <summary>The timestamp of when the message was created (issued).</summary>
        public DateTime IssuedAt { get { return Utility.FromTimestamp(this._claims.iat); } }
        /// <summary>The timestamp of when the message is expired and is no longer valid.</summary>
        public DateTime? ExpiresAt { get { return (this._claims.exp != null) ? Utility.FromTimestamp(this._claims.exp) : null; } }
        /// <summary>Normally used to specify a key that was used to encrypt the message. Used by the receiver to either complete
        /// a key agreement for a shared encryption key, or fetch a pre-shared enctyption key.
        public Guid? KeyId { get { return this._claims.kid; } set { ThrowIfSigned(); this._claims.kid = value; } }
        /// <summary>Normally used to attach a public key to a message that is encrypted. Used by the receiver to generate the shared 
        /// encryption key. Same as the "pub" field.</summary>
        public string PublicKey { get { return this._claims.pub; } set { ThrowIfSigned(); this._claims.pub = value; } }
        /// <summary>If another Dime item has been linked to this message, then this will be set the the 
        /// unique identifier, UUID, of that linked item. Will be null, if no item is linked.</summary>
        public Guid? LinkedId 
        { 
            get 
            { 
                if (this._claims.lnk != null)
                {
                    string uid = this._claims.lnk.Split(new char[] { Envelope._COMPONENT_DELIMITER })[Message._LINK_UID_INDEX];
                    return new Guid(uid);
                }
                return null; 
            } 
        }
        public string Context { get { return this._claims.ctx; } }

        #endregion
        #region -- PUBLIC CONSTRUCTORS --

        public Message() { }

        public Message(Guid issuerId, double validFor = -1, string context = null): this(null, issuerId, validFor, context) { }

        public Message(Guid? audienceId, Guid issuerId, double validFor = -1, string context = null)
        {
            if (context != null && context.Length > Envelope.MAX_CONTEXT_LENGTH) { throw new ArgumentException("Context must not be longer than " + Envelope.MAX_CONTEXT_LENGTH + "."); }
            DateTime iat = DateTime.UtcNow;
            DateTime? exp = (validFor != -1) ? iat.AddSeconds(validFor) : null; 
            this._claims = new MessageClaims(Guid.NewGuid(), 
                                             audienceId, 
                                             issuerId, 
                                             Utility.ToTimestamp(iat), 
                                             (exp.HasValue) ? Utility.ToTimestamp(exp.Value) : null, 
                                             null, 
                                             null, 
                                             null,
                                             context);
        }

        #endregion
        #region -- PUBLIC INTERFACE --

        public override void Sign(Key keybox)
        {
            if (this._payload == null) { throw new InvalidOperationException("Unable to sign message, no payload added."); }
            base.Sign(keybox);
        }

        public override string ToEncoded()
        {
            if (this._payload == null) { throw new InvalidOperationException("Unable to encode message, no payload added."); }
            return base.ToEncoded();
        }

        internal new static Message FromEncoded(string encoded)
        {
            Message message = new Message();
            message.Decode(encoded);
            return message;
        }

        public override void Verify(Key keybox) { 
            if (this._payload == null || this._payload.Length == 0) { throw new InvalidOperationException("Unable to verify message, no payload added."); }
            // Verify IssuedAt and ExpiresAt
            DateTime now = DateTime.UtcNow;
            if (this.IssuedAt > now) { throw new DateExpirationException("Issuing date in the future."); }
            if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Expiration before issuing date."); }
            if (this.ExpiresAt < now) { throw new DateExpirationException("Passed expiration date."); }
            base.Verify(keybox);
        }

        public void Verify(string publicKey, Item linkedItem)
        {
            Verify(new Key(publicKey), linkedItem);
        }

        public void Verify(Key keybox, Item linkedItem)
        {
            Verify(keybox);
            if (linkedItem != null)
            {
                if (this._claims.lnk == null || this._claims.lnk.Length == 0) { throw new InvalidOperationException("No link to Dime item found, unable to verify."); }
                string[] components = this._claims.lnk.Split(new char[] { Envelope._COMPONENT_DELIMITER });
                if (components == null || components.Length != 3) { throw new FormatException("Invalid data found in item link field."); }
                string msgHash = linkedItem.Thumbprint();
                if (components[Message._LINK_ITEM_TYPE_INDEX] != linkedItem.Tag
                    || components[Message._LINK_UID_INDEX] != linkedItem.UniqueId.ToString() 
                    || components[Message._LINK_THUMBPRINT_INDEX] != msgHash) 
                { throw new IntegrityException("Failed to verify link Dime item (provided item did not match)."); }
            }
        }

        /// <summary>Will attach a byte-array payload to the message. This may be any valid byte-array, at export this will be
        /// encoded as a Base64 string. If a payload is already set, then the old will be overwritten. If the message is already signed, 
        /// then InvalidOperationException will be thrown.</summary>
        /// <param name="payload">The payload to set.</param>
        public void SetPayload(byte[] payload) {
            ThrowIfSigned();
            this._payload = Utility.ToBase64(payload);
        }

        /// <summary>Will encrypt and attach a byte-array payload to the message. This may be any valid byte-array, at export this will be
        /// encoded as a Base64 string. If a payload is already set, then the old will be overwritten. If the message is already signed, 
        /// then InvalidOperationException will be thrown.</summary>
        /// <param name="payload">The payload to set.</param>
        /// <param name="localKey">The key of the sender (issuer), must include a secret (private) key.</param>
        /// <param name="remoteKey">The key of the receiver (audience), usually just the public key.</param>
        /// <param name="salt">An optional byte-array that will be included in the key generation.</param>
        public void SetPayload(byte[] payload, Key localKey, Key remoteKey, byte[] salt = null)
        {
            ThrowIfSigned();
            if (localKey == null || localKey.Secret == null) { throw new ArgumentNullException(nameof(localKey), "Provided local key may not be null."); }
            if (remoteKey == null || remoteKey.Public == null) { throw new ArgumentNullException(nameof(remoteKey), "Provided remote key may not be null."); }
            if (this.AudienceId == null) { throw new InvalidOperationException("AudienceId must be set in the message for encrypted payloads."); }
            if (localKey.Type != KeyType.Exchange) { throw new ArgumentException("Unable to encrypt, local key of invalid key type.", nameof(localKey)); }
            if (remoteKey.Type != KeyType.Exchange) { throw new ArgumentException("Unable to encrypt, remote key invalid key type.", nameof(remoteKey)); }
            byte[] info = Crypto.GenerateHash(Utility.Combine(this.IssuerId.ToByteArray(), this.AudienceId.Value.ToByteArray()));
            var key = Crypto.GenerateSharedSecret(localKey, remoteKey, salt, info);
            SetPayload(Crypto.Encrypt(payload, key));
        }

        /// <summary>Returns the payload attached to the message. This method will not decrypt any encrypted payloads, just return 
        /// the byte-array as is.</summary>
        /// <returns>A byte-array.</returns>
        public byte[] GetPayload() {
            return Utility.FromBase64(this._payload);
        }

        /// <summary>Decrypts and returns the payload attached to the message. This will decrypt the payload before returning it.</summary>
        /// <param name="localKey">The key of the sender (audience), must include a secret (private) key.</param>
        /// <param name="remoteKey">The key of the receiver (issuer), usually just the public key.</param>
        /// <param name="salt">An optional byte-array that will be included in the key generation.</param>
        /// <returns>A byte-array.</returns>
        public byte[] GetPayload(Key localKey, Key remoteKey, byte[] salt = null)
        {
            if (localKey == null) { throw new ArgumentNullException(nameof(localKey), "Provided local key may not be null."); }
            if (remoteKey == null || remoteKey.Public == null) { throw new ArgumentNullException(nameof(remoteKey), "Provided remote key may not be null."); }
            if (this.AudienceId == null) { throw new FormatException("AudienceId (aud) missing in message, unable to dectrypt payload."); }
            if (localKey.Type != KeyType.Exchange) { throw new ArgumentException("Unable to decrypt, invalid key type.", nameof(localKey)); }
            if (localKey.Secret == null) { throw new ArgumentNullException(nameof(localKey), "Unable to decrypt, key must not be null."); }
            byte[] info = Crypto.GenerateHash(Utility.Combine(this.IssuerId.ToByteArray(), this.AudienceId.Value.ToByteArray()));
            var key = Crypto.GenerateSharedSecret(localKey, remoteKey, salt, info);
            return Crypto.Decrypt(GetPayload(), key);
        }

        /// <summary>This will link another Dime item to this message. Used most often when responding to another message.
        /// The Dime item is then cryptographically linked to the response message, once the message is signed.</summary>
        /// <param name="item">The message object to link to.</param>
        /// <exception cref="ArgumentNullException">If the passed message object is null.</exception> 
        public void LinkItem(Item item)
        {
            if (this.IsSigned) { throw new InvalidOperationException("Unable to link item, message is already signed."); }
            if (item == null) { throw new ArgumentNullException(nameof(item), "Item to link with must not be null."); }
            this._claims.lnk = $"{item.Tag}{Envelope._COMPONENT_DELIMITER}{item.UniqueId.ToString()}{Envelope._COMPONENT_DELIMITER}{item.Thumbprint()}";
        }

        #endregion

        #region -- INTERNAL --

        #endregion

        # region -- PROTECTED --

        protected override void Decode(string encoded)
        {
            string[] components = encoded.Split(new char[] { Envelope._COMPONENT_DELIMITER });
            if (components.Length != Message._NBR_EXPECTED_COMPONENTS_NO_SIGNATURE
            || components.Length != Message._NBR_EXPECTED_COMPONENTS_SIGNATURE) 
                { throw new FormatException($"Unexpected number of components for identity issuing request, expected: '{Message._NBR_EXPECTED_COMPONENTS_NO_SIGNATURE}' or '{Message._NBR_EXPECTED_COMPONENTS_SIGNATURE}', got: '{components.Length}'."); }
            if (components[Message._TAG_INDEX] != Message.TAG) { throw new FormatException($"Unexpected item tag, expected: \"{Message.TAG}\", got: \"{components[Message._TAG_INDEX]}\"."); }
            this._claims = JsonSerializer.Deserialize<MessageClaims>(Utility.FromBase64(components[Message._CLAIMS_INDEX]));
            this._payload = components[Message._PAYLOAD_INDEX];
            if (components.Length == Message._NBR_EXPECTED_COMPONENTS_SIGNATURE)
            {
                this._signature = components.Last();
            }
        }

        protected override string Encode()
        {
            if (this._encoded == null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(Message.TAG);
                builder.Append(Envelope._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                builder.Append(Envelope._COMPONENT_DELIMITER);
                builder.Append(this._payload);
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

        #region -- PRIVATE --

        private const int _NBR_EXPECTED_COMPONENTS_SIGNATURE = 4;
        private const int _NBR_EXPECTED_COMPONENTS_NO_SIGNATURE = 4;
        private const int _TAG_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;
        private const int _PAYLOAD_INDEX = 2;
        private const int _LINK_ITEM_TYPE_INDEX = 0;
        private const int _LINK_UID_INDEX = 1;
        private const int _LINK_THUMBPRINT_INDEX = 2;
        private MessageClaims _claims;
        private string _payload;

        private struct MessageClaims
        {
            public Guid uid { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public Guid? aud { get; set; }
            public Guid iss { get; set; }
            public string iat { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string exp { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public Guid? kid { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string pub { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string lnk { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string ctx { get; set; }

            [JsonConstructor]
            public MessageClaims(Guid uid, Guid? aud, Guid iss, string iat, string exp, Guid? kid, string pub, string lnk, string ctx)
            {
                this.uid = uid;
                this.aud = aud;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
                this.kid = kid;
                this.pub = pub;
                this.lnk = lnk;
                this.ctx = ctx;
            }
        }

        #endregion

    }

}
