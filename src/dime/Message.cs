//
//  Message.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
// 
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

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
        public const string ItemIdentifier = "MSG"; 
        /// <summary>
        /// Returns the tag of the Di:ME item.
        /// </summary>
        public override string Identifier => ItemIdentifier;
        /// <summary>
        /// Returns the audience (receiver) identifier. This is optional, although required if encrypting the message
        /// payload.
        /// </summary>
        public Guid? AudienceId => Claims().GetGuid(Claim.Aud);
        /// <summary>
        /// The identifier of the key that was used when encryption the message payload. This is optional, and usage is
        /// application specific.
        /// </summary>
        public Guid? KeyId { get => Claims().Get<Guid>(Claim.Kid); set { ThrowIfSigned(); Claims().Put(Claim.Kid, value); } }
        /// <summary>
        /// A public key that was included in the message. Normally this public key was used for a key exchange where
        /// the shared key was used to encrypt the payload. This is optional.
        /// </summary>
        public string PublicKey { get => Claims().Get<string>(Claim.Pub); set { ThrowIfSigned(); Claims().Put(Claim.Pub, value); } }
        /// <summary>
        /// If the message is linked to another Di:ME item, thus creating a cryptographic link between them, then this
        /// will return the identifier, as a UUID, of the linked item. This is optional.
        /// </summary>
        public Guid? LinkedId 
        { 
            get
            {
                var lnk = Claims().Get<string>(Claim.Lnk);
                if (lnk is null) return null;
                var uid = lnk.Split(new[] { Dime.ComponentDelimiter })[LinkUidIndex];
                return new Guid(uid);
            } 
        }

        #endregion
        
        #region -- PUBLIC CONSTRUCTORS --

        /// <summary>
        /// Empty constructor, not to be used. Required for Generics.
        /// </summary>
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
            if (context is {Length: > Dime.MaxContextLength}) { throw new ArgumentException("Context must not be longer than " + Dime.MaxContextLength + "."); }
            var iat = DateTime.UtcNow;
            DateTime? exp = validFor != -1 ? iat.AddSeconds(validFor) : null;
            var claims = Claims();
            claims.Put(Claim.Uid, Guid.NewGuid());
            claims.Put(Claim.Aud, audienceId);
            claims.Put(Claim.Iss, issuerId);
            claims.Put(Claim.Iat, iat);
            claims.Put(Claim.Exp, exp);
            claims.Put(Claim.Ctx, context);
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
        /// <param name="key">The key to used to verify the signature, must not be null.</param>
        /// <param name="linkedItem">The item the message was linked to.</param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="FormatException">If no item has been linked with the message.</exception>
        /// <exception cref="IntegrityException">If the signature is invalid.</exception>
        public void Verify(Key key, Item linkedItem)
        {
            Verify(key);
            if (linkedItem == null) return;
            if (string.IsNullOrEmpty(Claims().Get<string>(Claim.Lnk))) { throw new InvalidOperationException("No link to Dime item found, unable to verify."); }
            var item = Claims().Get<string>(Claim.Lnk).Split(new[] { Dime.SectionDelimiter })[0]; // This is in preparation of a future change where it would be possible to link more than one item
            var components = item.Split(new[] { Dime.ComponentDelimiter });
            if (components is not {Length: 3}) { throw new FormatException("Invalid data found in item link field."); }
            var msgHash = linkedItem.Thumbprint();
            if (components[LinkItemTypeIndex] != linkedItem.Identifier
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
            if (payload == null || payload.Length == 0) { throw new ArgumentException("Unable to set payload, payload must not be null or empty."); }
            if (issuerKey == null) { throw new ArgumentNullException(nameof(issuerKey), "Unable to encrypt, issuer key must not be null."); }
            if (audienceKey == null) { throw new ArgumentNullException(nameof(audienceKey), "Unable to encrypt, audience key may not be null."); }
            var sharedKey = issuerKey.GenerateSharedSecret(audienceKey, new List<KeyUse>() { KeyUse.Encrypt });
            SetPayload(Dime.Crypto.Encrypt(payload, sharedKey));
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
            if (issuerKey == null) { throw new ArgumentNullException(nameof(issuerKey), "Unable to decrypt, issuer key may not be null."); }
            if (audienceKey == null) { throw new ArgumentNullException(nameof(audienceKey), "Unable to decrypt, audience key may not be null."); }
            var sharedKey = issuerKey.GenerateSharedSecret(audienceKey, new List<KeyUse>() { KeyUse.Encrypt });
            return Dime.Crypto.Decrypt(GetPayload(), sharedKey);
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
            Claims().Put(Claim.Lnk, $"{item.Identifier}{Dime.ComponentDelimiter}{item.UniqueId.ToString()}{Dime.ComponentDelimiter}{item.Thumbprint()}");
        }

        #endregion

        #region -- INTERNAL --
/*
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
    */    
        #endregion

        # region -- PROTECTED --

        internal override string ForExport()
        {
            if (!IsSigned) throw new InvalidOperationException("Unable to encode item, must be signed first.");
            return base.ForExport();
        }

        protected override void CustomDecoding(List<string> components)
        {
            if (components.Count > MaximumNbrComponents)
                throw new FormatException(
                    $"More components in item than expected, got {components.Count}, expected maximum {MaximumNbrComponents}.");
            _payload = components[ComponentsPayloadIndex];
            IsSigned = true; // Messages are always signed
        }

        protected override void CustomEncoding(StringBuilder builder)
        {
            base.CustomEncoding(builder);
            builder.Append(Dime.ComponentDelimiter);
            builder.Append(_payload);
        }

        protected override int GetMinNbrOfComponents()
        {
            return MinimumNbrComponents;
        }

/*        
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
*/
        #endregion

        #region -- PRIVATE --
        
        private new const int MinimumNbrComponents = 4;
        private const int MaximumNbrComponents = MinimumNbrComponents + 1;
        private const int ComponentsPayloadIndex = 2;

        private const int LinkItemTypeIndex = 0;
        private const int LinkUidIndex = 1;
        private const int LinkThumbprintIndex = 2;
        private string _payload;

        #endregion

    }

}
