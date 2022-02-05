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
    /// optionally encrypted (using end-to-end encryption). Responses to messages may be linked with the original message, thus
    /// creating a strong cryptographical link. The entity that created the message signs it before exporting and thus sealing
    /// it's content. </summary>
    public class Message: Item
    {
        #region -- PUBLIC DATA MEMBERS --
        public const string _TAG = "MSG"; 
        public override string Tag => _TAG;
        /// <summary>A unique identifier for the message.</summary>
        public override Guid UniqueId => _claims.uid;
        /// <summary>The id of the receiver.</summary>
        public Guid? AudienceId => _claims.aud;
        /// <summary>The id of the issuer (subject id of the issuer).</summary>
        public Guid IssuerId => _claims.iss;
        /// <summary>The timestamp of when the message was created (issued).</summary>
        public DateTime IssuedAt => Utility.FromTimestamp(_claims.iat);
        /// <summary>The timestamp of when the message is expired and is no longer valid.</summary>
        public DateTime? ExpiresAt => (_claims.exp != null) ? Utility.FromTimestamp(_claims.exp) : null;
        /// <summary>Normally used to specify a key that was used to encrypt the message. Used by the receiver to either complete
        /// a key agreement for a shared encryption key, or fetch a pre-shared encryption key.</summary>
        public Guid? KeyId { get => _claims.kid; set { ThrowIfSigned(); _claims.kid = value; } }
        /// <summary>Normally used to attach a public key to a message that is encrypted. Used by the receiver to generate the shared 
        /// encryption key. Same as the "pub" field.</summary>
        public string PublicKey { get => _claims.pub; set { ThrowIfSigned(); _claims.pub = value; } }
        /// <summary>If another Dime item has been linked to this message, then this will be set the the 
        /// unique identifier, UUID, of that linked item. Will be null, if no item is linked.</summary>
        public Guid? LinkedId 
        { 
            get 
            {
                if (_claims.lnk == null) return null;
                var uid = _claims.lnk.Split(new[] { Envelope._COMPONENT_DELIMITER })[LinkUidIndex];
                return new Guid(uid);
            } 
        }
        public string Context => _claims.ctx;

        #endregion
        
        #region -- PUBLIC CONSTRUCTORS --

        public Message() { }

        public Message(Guid issuerId, double validFor = -1, string context = null): this(null, issuerId, validFor, context) { }

        public Message(Guid? audienceId, Guid issuerId, double validFor = -1, string context = null)
        {
            if (context is {Length: > Envelope._MAX_CONTEXT_LENGTH}) { throw new ArgumentException("Context must not be longer than " + Envelope._MAX_CONTEXT_LENGTH + "."); }
            var iat = DateTime.UtcNow;
            DateTime? exp = (validFor != -1) ? iat.AddSeconds(validFor) : null; 
            _claims = new MessageClaims(Guid.NewGuid(), 
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

        public override void Sign(Key key)
        {
            if (_payload == null) { throw new InvalidOperationException("Unable to sign message, no payload added."); }
            base.Sign(key);
        }

        public override string ToEncoded()
        {
            if (_payload == null) { throw new InvalidOperationException("Unable to encode message, no payload added."); }
            return base.ToEncoded();
        }

        internal new static Message FromEncoded(string encoded)
        {
            var message = new Message();
            message.Decode(encoded);
            return message;
        }

        public override void Verify(Key key) { 
            if (string.IsNullOrEmpty(_payload)) { throw new InvalidOperationException("Unable to verify message, no payload added."); }
            // Verify IssuedAt and ExpiresAt
            var now = DateTime.UtcNow;
            if (IssuedAt > now) { throw new DateExpirationException("Issuing date in the future."); }
            if (ExpiresAt != null) {
                if (IssuedAt > ExpiresAt) { throw new DateExpirationException("Expiration before issuing date."); }
                if (ExpiresAt < now) { throw new DateExpirationException("Passed expiration date."); }
            }
            base.Verify(key);
        }

        public void Verify(string publicKey, Item linkedItem)
        {
            Verify(new Key(publicKey), linkedItem);
        }

        public void Verify(Key key, Item linkedItem)
        {
            Verify(key);
            if (linkedItem == null) return;
            if (string.IsNullOrEmpty(_claims.lnk)) { throw new InvalidOperationException("No link to Dime item found, unable to verify."); }
            var components = _claims.lnk.Split(new[] { Envelope._COMPONENT_DELIMITER });
            if (components is not {Length: 3}) { throw new FormatException("Invalid data found in item link field."); }
            var msgHash = linkedItem.Thumbprint();
            if (components[LinkItemTypeIndex] != linkedItem.Tag
                || components[LinkUidIndex] != linkedItem.UniqueId.ToString() 
                || components[LinkThumbprintIndex] != msgHash) 
            { throw new IntegrityException("Failed to verify link Dime item (provided item did not match)."); }
        }

        /// <summary>Will attach a byte-array payload to the message. This may be any valid byte-array, at export this will be
        /// encoded as a Base64 string. If a payload is already set, then the old will be overwritten. If the message is already signed, 
        /// then InvalidOperationException will be thrown.</summary>
        /// <param name="payload">The payload to set.</param>
        public void SetPayload(byte[] payload) {
            ThrowIfSigned();
            _payload = Utility.ToBase64(payload);
        }

        /// <summary>Will encrypt and attach a byte-array payload to the message. This may be any valid byte-array, at export this will be
        /// encoded as a Base64 string. If a payload is already set, then the old will be overwritten. If the message is already signed, 
        /// then InvalidOperationException will be thrown.</summary>
        /// <param name="payload">The payload to set.</param>
        /// <param name="issuerKey">This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.</param>
        /// <param name="audienceKey">This is the key of the audience of the message, must be of type EXCHANGE, must not be null.</param>
        public void SetPayload(byte[] payload, Key issuerKey, Key audienceKey)
        {
            ThrowIfSigned();
            if (issuerKey == null) { throw new ArgumentNullException(nameof(issuerKey), "Provided local key may not be null."); }
            if (audienceKey == null) { throw new ArgumentNullException(nameof(audienceKey), "Provided remote key may not be null."); }
            if (issuerKey.Type != KeyType.Exchange) { throw new ArgumentException("Unable to encrypt, local key of invalid key type.", nameof(issuerKey)); }
            if (audienceKey.Type != KeyType.Exchange) { throw new ArgumentException("Unable to encrypt, remote key invalid key type.", nameof(audienceKey)); }
            var key = Crypto.GenerateSharedSecret(issuerKey, audienceKey);
            SetPayload(Crypto.Encrypt(payload, key));
        }

        /// <summary>Returns the payload attached to the message. This method will not decrypt any encrypted payloads, just return 
        /// the byte-array as is.</summary>
        /// <returns>A byte-array.</returns>
        public byte[] GetPayload() {
            return Utility.FromBase64(_payload);
        }

        /// <summary>Decrypts and returns the payload attached to the message. This will decrypt the payload before returning it.</summary>
        /// <param name="issuerKey">This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.</param>
        /// <param name="audienceKey">This is the key of the audience of the message, must be of type EXCHANGE, must not be null.</param>
        /// <returns>A byte-array.</returns>
        public byte[] GetPayload(Key issuerKey, Key audienceKey)
        {
            if (issuerKey == null) { throw new ArgumentNullException(nameof(issuerKey), "Provided local key may not be null."); }
            if (audienceKey?.Public == null) { throw new ArgumentNullException(nameof(audienceKey), "Provided remote key may not be null."); }
            if (issuerKey.Type != KeyType.Exchange) { throw new ArgumentException("Unable to decrypt, invalid key type.", nameof(issuerKey)); }
            var key = Crypto.GenerateSharedSecret(issuerKey, audienceKey);
            return Crypto.Decrypt(GetPayload(), key);
        }

        /// <summary>This will link another Dime item to this message. Used most often when responding to another message.
        /// The Dime item is then cryptographically linked to the response message, once the message is signed.</summary>
        /// <param name="item">The message object to link to.</param>
        /// <exception cref="ArgumentNullException">If the passed message object is null.</exception> 
        public void LinkItem(Item item)
        {
            if (IsSigned) { throw new InvalidOperationException("Unable to link item, message is already signed."); }
            if (item == null) { throw new ArgumentNullException(nameof(item), "Item to link with must not be null."); }
            _claims.lnk = $"{item.Tag}{Envelope._COMPONENT_DELIMITER}{item.UniqueId.ToString()}{Envelope._COMPONENT_DELIMITER}{item.Thumbprint()}";
        }

        #endregion

        #region -- INTERNAL --

        #endregion

        # region -- PROTECTED --

        protected override void Decode(string encoded)
        {
            var components = encoded.Split(new[] { Envelope._COMPONENT_DELIMITER });
            if (components.Length is not (NbrExpectedComponentsNoSignature and NbrExpectedComponentsSignature)) 
            { throw new FormatException($"Unexpected number of components for identity issuing request, expected: '{NbrExpectedComponentsNoSignature}' or '{NbrExpectedComponentsSignature}', got: '{components.Length}'."); }
            if (components[TagIndex] != _TAG) { throw new FormatException($"Unexpected item tag, expected: \"{_TAG}\", got: \"{components[TagIndex]}\"."); }
            _claims = JsonSerializer.Deserialize<MessageClaims>(Utility.FromBase64(components[ClaimsIndex]));
            _payload = components[PayloadIndex];
            if (components.Length == NbrExpectedComponentsSignature)
            {
                Signature = components.Last();
            }
        }

        protected override string Encode()
        {
            if (Encoded != null) return Encoded;
            var builder = new StringBuilder();
            builder.Append(_TAG);
            builder.Append(Envelope._COMPONENT_DELIMITER);
            builder.Append(Utility.ToBase64(JsonSerializer.Serialize(_claims)));
            builder.Append(Envelope._COMPONENT_DELIMITER);
            builder.Append(_payload);
            Encoded = builder.ToString();
            return Encoded;
        }

        #endregion

        #region -- PRIVATE --

        private const int NbrExpectedComponentsSignature = 4;
        private const int NbrExpectedComponentsNoSignature = 4;
        private const int TagIndex = 0;
        private const int ClaimsIndex = 1;
        private const int PayloadIndex = 2;
        private const int LinkItemTypeIndex = 0;
        private const int LinkUidIndex = 1;
        private const int LinkThumbprintIndex = 2;
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
