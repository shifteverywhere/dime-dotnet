//
//  Message.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;

namespace DiME
{
    /// <summary>
    /// A class that can be used to create secure and integrity protected messages, that can be sent to entities, who
    /// may verify the integrity and trust of the message. Messages may also be end-to-end encrypted to protect the
    /// confidentiality of the message payload.
    /// </summary>
    public class Message: Item
    {
        #region -- PUBLIC DATA MEMBERS --
        
        /// <summary>
        /// A tag identifying the Di:ME item type, part of the header.
        /// </summary>
        public const string _TAG = "MSG"; 
        /// <summary>
        /// Returns the tag of the Di:ME item.
        /// </summary>
        public override string Tag => _TAG;
        /// <summary>
        /// Returns a unique identifier for the instance. This will be generated at instance creation.
        /// </summary>
        public override Guid UniqueId => _claims.uid;
        /// <summary>
        /// Returns the audience (receiver) identifier. This is optional, although required if encrypting the message
        /// payload.
        /// </summary>
        public Guid? AudienceId => _claims.aud;
        /// <summary>
        /// Returns the issuer (sender/creator) identifier of the message.
        /// </summary>
        public Guid IssuerId => _claims.iss;
        /// <summary>
        /// The date and time when this message was created.
        /// </summary>
        public DateTime IssuedAt => Utility.FromTimestamp(_claims.iat);
        /// <summary>
        /// The date and time when the message will expire.
        /// </summary>
        public DateTime? ExpiresAt => (_claims.exp != null) ? Utility.FromTimestamp(_claims.exp) : null;
        /// <summary>
        /// The identifier of the key that was used when encryption the message payload. This is optional, and usage is
        /// application specific.
        /// </summary>
        public Guid? KeyId { get => _claims.kid; set { ThrowIfSigned(); _claims.kid = value; } }
        /// <summary>
        /// A public key that was included in the message. Normally this public key was used for a key exchange where
        /// the shared key was used to encrypt the payload. This is optional.
        /// </summary>
        public string PublicKey { get => _claims.pub; set { ThrowIfSigned(); _claims.pub = value; } }
        /// <summary>
        /// If the message is linked to another Di:ME item, thus creating a cryptographic link between them, then this
        /// will return the identifier, as a UUID, of the linked item. This is optional.
        /// </summary>
        public Guid? LinkedId 
        { 
            get 
            {
                if (_claims.lnk == null) return null;
                var uid = _claims.lnk.Split(new[] { Dime.ComponentDelimiter })[LinkUidIndex];
                return new Guid(uid);
            } 
        }
        /// <summary>
        /// Returns the context that is attached to the message.
        /// </summary>
        public string Context => _claims.ctx;

        #endregion
        
        #region -- PUBLIC CONSTRUCTORS --

        public Message() { }

        /// <summary>
        /// Creates a message from a specified issuer (sender) and an expiration date.
        /// </summary>
        /// <param name="issuerId">The issuer identifier.</param>
        /// <param name="validFor">The number of seconds that the message should be valid for, from the time of issuing.</param>
        /// <param name="context">The context to attach to the message, may be null.</param>
        public Message(Guid issuerId, long validFor = -1L, string context = null): this(null, issuerId, validFor, context) { }

        /// <summary>
        /// Creates a message to a specified audience (receiver) from a specified issuer (sender), with an expiration
        /// date and a context. The context may be anything and may be used for application specific purposes.
        /// </summary>
        /// <param name="audienceId">The audience identifier. Providing -1 as validFor will skip setting an expiration
        /// date.</param>
        /// <param name="issuerId">The issuer identifier.</param>
        /// <param name="validFor">The number of seconds that the message should be valid for, from the time of issuing.</param>
        /// <param name="context">The context to attach to the message, may be null.</param>
        /// <exception cref="ArgumentException"></exception>
        public Message(Guid? audienceId, Guid issuerId, long validFor = -1L, string context = null)
        {
            if (context is {Length: > Envelope._MAX_CONTEXT_LENGTH}) { throw new ArgumentException("Context must not be longer than " + Envelope._MAX_CONTEXT_LENGTH + "."); }
            var iat = DateTime.UtcNow;
            DateTime? exp = validFor != -1 ? iat.AddSeconds(validFor) : null; 
            _claims = new MessageClaims(Guid.NewGuid(), 
                audienceId, 
                issuerId, 
                Utility.ToTimestamp(iat), 
                exp.HasValue ? Utility.ToTimestamp(exp.Value) : null, 
                null, 
                null, 
                null,
                context);
        }

        #endregion
        
        #region -- PUBLIC INTERFACE --

        /// <summary>
        /// Will sign the message with the proved key. The Key instance must contain a secret key and be of type IDENTITY.
        /// </summary>
        /// <param name="key">The key to sign the item with, must be of type IDENTITY.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public override void Sign(Key key)
        {
            if (_payload == null) { throw new InvalidOperationException("Unable to sign message, no payload added."); }
            base.Sign(key);
        }

        /// <summary>
        /// Verifies the signature of the message using a provided key.
        /// </summary>
        /// <param name="key">The key to used to verify the signature, must not be null.</param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="DateExpirationException">If any problems with issued at and expires at dates.</exception>
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

        /// <summary>
        /// Verifies the signature of the message using a provided key and verifies a linked item from the proved item.
        /// To verify correctly the linkedItem must be the original item that the message was linked to.
        /// </summary>
        /// <param name="publicKey">The key to used to verify the signature, must not be null.</param>
        /// <param name="linkedItem">The item the message was linked to.</param>
        public void Verify(string publicKey, Item linkedItem)
        {
            Verify(new Key(publicKey), linkedItem);
        }

        /// <summary>
        /// Verifies the signature of the message using a provided key and verifies a linked item from the proved item.
        /// To verify correctly the linkedItem must be the original item that the message was linked to.
        /// </summary>
        /// <param name="key">The key to used to verify the signature, must not be null.</param>
        /// <param name="linkedItem">The item the message was linked to.</param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="FormatException">If no item has been linked with the message.</exception>
        /// <exception cref="IntegrityException">If the signature is invalid.</exception>
        public void Verify(Key key, Item linkedItem)
        {
            Verify(key);
            if (linkedItem == null) return;
            if (string.IsNullOrEmpty(_claims.lnk)) { throw new InvalidOperationException("No link to Dime item found, unable to verify."); }
            var item = _claims.lnk.Split(new[] { Dime.SectionDelimiter })[0]; // This is in preparation of a future change where it would be possible to link more than one item
            var components = item.Split(new[] { Dime.ComponentDelimiter });
            if (components is not {Length: 3}) { throw new FormatException("Invalid data found in item link field."); }
            var msgHash = linkedItem.Thumbprint();
            if (components[LinkItemTypeIndex] != linkedItem.Tag
                || components[LinkUidIndex] != linkedItem.UniqueId.ToString() 
                || components[LinkThumbprintIndex] != msgHash) 
            { throw new IntegrityException("Failed to verify link Dime item (provided item did not match)."); }
        }
        
        /// <summary>
        /// Sets the plain text payload of the message.
        /// </summary>
        /// <param name="payload">The payload to set.</param>
        public void SetPayload(byte[] payload) {
            ThrowIfSigned();
            _payload = Utility.ToBase64(payload);
        }

        /// <summary>
        /// Will encrypt and attach a payload using a shared encryption key between the issuer and audience of a message.
        /// </summary>
        /// <param name="payload">The payload to encrypt and attach to the message, must not be null and of length >= 1.</param>
        /// <param name="issuerKey">This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.</param>
        /// <param name="audienceKey">This is the key of the audience of the message, must be of type EXCHANGE, must not be null.</param>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
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

        /// <summary>
        /// Returns the plain text payload of the message. If an encrypted payload have been set, then this will return
        /// the encrypted payload.
        /// </summary>
        /// <returns>The message payload.</returns>
        public byte[] GetPayload() {
            return Utility.FromBase64(_payload);
        }

        /// <summary>
        /// Returns the decrypted message payload, if it is able to decrypt it.
        /// </summary>
        /// <param name="issuerKey">This is the key of the issuer of the message, must be of type EXCHANGE, must not be null.</param>
        /// <param name="audienceKey">This is the key of the audience of the message, must be of type EXCHANGE, must not be null.</param>
        /// <returns>The message payload.</returns>
        /// <exception cref="ArgumentNullException"></exception>
        /// <exception cref="ArgumentException"></exception>
        public byte[] GetPayload(Key issuerKey, Key audienceKey)
        {
            if (issuerKey == null) { throw new ArgumentNullException(nameof(issuerKey), "Provided local key may not be null."); }
            if (audienceKey?.Public == null) { throw new ArgumentNullException(nameof(audienceKey), "Provided remote key may not be null."); }
            if (issuerKey.Type != KeyType.Exchange) { throw new ArgumentException("Unable to decrypt, invalid key type.", nameof(issuerKey)); }
            var key = Crypto.GenerateSharedSecret(issuerKey, audienceKey);
            return Crypto.Decrypt(GetPayload(), key);
        }

        /// <summary>
        /// Will cryptographically link a message to another Di:ME item. This may be used to prove a relationship
        /// between one message and other item.
        /// </summary>
        /// <param name="item">The item to link to the message.</param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public void LinkItem(Item item)
        {
            if (IsSigned) { throw new InvalidOperationException("Unable to link item, message is already signed."); }
            if (item == null) { throw new ArgumentNullException(nameof(item), "Item to link with must not be null."); }
            _claims.lnk = $"{item.Tag}{Dime.ComponentDelimiter}{item.UniqueId.ToString()}{Dime.ComponentDelimiter}{item.Thumbprint()}";
        }

        #endregion

        #region -- INTERNAL --

        internal override string ToEncoded()
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
        
        #endregion

        # region -- PROTECTED --

        protected override void Decode(string encoded)
        {
            var components = encoded.Split(new[] { Dime.ComponentDelimiter });
            if (components.Length is not NbrExpectedComponents) 
            { throw new FormatException($"Unexpected number of components for identity issuing request, expected: '{NbrExpectedComponents}' or , got: '{components.Length}'."); }
            if (components[TagIndex] != _TAG) { throw new FormatException($"Unexpected item tag, expected: \"{_TAG}\", got: \"{components[TagIndex]}\"."); }
            _claims = JsonSerializer.Deserialize<MessageClaims>(Utility.FromBase64(components[ClaimsIndex]));
            _payload = components[PayloadIndex];
            Encoded = encoded[..encoded.LastIndexOf(Dime.ComponentDelimiter)];
            Signature = components.Last();
        }

        protected override string Encode()
        {
            if (Encoded != null) return Encoded;
            var builder = new StringBuilder();
            builder.Append(_TAG);
            builder.Append(Dime.ComponentDelimiter);
            builder.Append(Utility.ToBase64(JsonSerializer.Serialize(_claims)));
            builder.Append(Dime.ComponentDelimiter);
            builder.Append(_payload);
            Encoded = builder.ToString();
            return Encoded;
        }

        #endregion

        #region -- PRIVATE --

        private const int NbrExpectedComponents = 4;
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
