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
using System.Linq;

namespace ShiftEverywhere.DiME
{
    ///<summary>Holds a message from one subject (issuer) to another. The actual message is held as a byte[] and may be
    /// optionally encrypted (using end-to-end encryption). Responses to messages may be linked with the orginal message, thus
    /// creating a strong cryptographical link. The entity that created the message signs it before exporting and thus sealing
    /// it's content. </summary>
    public class Message: Item
    {
        #region -- PUBLIC --

        public const string TAG = "MSG"; 
        public override string Tag { get { return Message.TAG; } }
        /// <summary>A unique identity for the message.</summary>
        public override Guid UID { get { return this._claims.uid; } }
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

        public Message() { }

        public Message(Guid audienceId, Guid issuerId, long? validFor = null)
        {
            long iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long? exp = (validFor.HasValue && validFor.Value > 0) ? iat + validFor.Value : null; 
            this._claims = new _MessageClaims(Guid.NewGuid(), audienceId, issuerId, iat, exp, null, null, null);
        }

        public override void Sign(KeyBox keybox)
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

        public override void Verify(KeyBox keybox) { 
            if (this._payload == null || this._payload.Length == 0) { throw new InvalidOperationException("Unable to verify message, no payload added."); }
            // Verify IssuedAt and ExpiresAt
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (this.IssuedAt > now) { throw new DateExpirationException("Issuing date in the future."); }
            if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Expiration before issuing date."); }
            if (this.ExpiresAt < now) { throw new DateExpirationException("Passed expiration date."); }
            base.Verify(keybox);
        }

        public void Verify(string publicKey, Item linkedItem)
        {
            Verify(new KeyBox(publicKey), linkedItem);
        }

        public void Verify(KeyBox keybox, Item linkedItem)
        {
            Verify(keybox);
            if (linkedItem != null)
            {
                if (this._claims.lnk == null || this._claims.lnk.Length == 0) { throw new FormatException("No link to Dime item found, unable to verify."); }
                string[] components = this._claims.lnk.Split(new char[] { Envelope._COMPONENT_DELIMITER });
                if (components == null || components.Length != 3) { throw new FormatException("Invalid data found in item link field."); }
                string msgHash = linkedItem.Thumbprint();
                if (components[Message._LINK_ITEM_TYPE_INDEX] != linkedItem.Tag
                    || components[Message._LINK_UID_INDEX] != linkedItem.UID.ToString() 
                    || components[Message._LINK_THUMBPRINT_INDEX] != msgHash) 
                { throw new IntegrityException("Failed to verify link Dime item (provided item did not match)."); }
            }
        }

        /// <summary>Will set a message payload. This may be any valid byte-array, at export this will be
        /// encoded as a Base64 string. If a payload is already set, then the old will be overwritten.</summary>
        /// <param name="payload">The payload to set.</param>
        public void SetPayload(byte[] payload)
        {
            this._payload = Utility.ToBase64(payload);
        }

        /// <summary>Returns the payload inside the message.</summary>
        /// <returns>A byte-array.</returns>
        public byte[] GetPayload()
        {
            return Utility.FromBase64(this._payload);
        }

        /// <summary>This will link another Dime item to this message. Used most often when responding to another message.
        /// The Dime item is then cryptographically linked to the response message, once the message is signed.</summary>
        /// <param name="item">The message object to link to.</param>
        /// <exception cref="ArgumentNullException">If the passed message object is null.</exception> 
        public void LinkItem(Item item)
        {
            if (this.IsSigned) { throw new InvalidOperationException("Unable to link item, message is already signed."); }
            if (item == null) { throw new ArgumentNullException(nameof(item), "Item to link with must not be null."); }
            this._claims.lnk = $"{item.Tag}{Envelope._COMPONENT_DELIMITER}{item.UID.ToString()}{Envelope._COMPONENT_DELIMITER}{item.Thumbprint()}";
        }

        #endregion

        #region -- INTERNAL --

        #endregion

        # region -- PROTECTED --

        protected override void Decode(string encoded)
        {
            string[] components = encoded.Split(new char[] { Envelope._COMPONENT_DELIMITER });
            if (components.Length != Message._NBR_EXPECTED_COMPONENTS_NO_SIGNATURE
            || components.Length != Message._NBR_EXPECTED_COMPONENTS_SIGNATURE) 
                { throw new FormatException($"Unexpected number of components for identity issuing request, expected '{Message._NBR_EXPECTED_COMPONENTS_NO_SIGNATURE}' or '{Message._NBR_EXPECTED_COMPONENTS_SIGNATURE}', got '{components.Length}'."); }
            if (components[Message._TAG_INDEX] != Message.TAG) { throw new FormatException($"Unexpected item tag, expected: \"{Message.TAG}\", got \"{components[Message._TAG_INDEX]}\"."); }
            this._claims = JsonSerializer.Deserialize<_MessageClaims>(Utility.FromBase64(components[Message._CLAIMS_INDEX]));
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
        private _MessageClaims _claims;
        private string _payload;

        private struct _MessageClaims
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
            public _MessageClaims(Guid uid, Guid aud, Guid iss, long iat, long? exp, Guid? kid, string xky, string lnk)
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
