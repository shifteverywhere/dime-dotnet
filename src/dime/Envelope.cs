//
//  Envelope.cs
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
using System.Collections.Generic;

namespace ShiftEverywhere.DiME
{
    ///<summary>Acts as a container object for Message instances. Several messages, independent on their origin
    /// may be added to an envelope. The entity that created the envelope signs it before exporting and thus sealing
    /// it's content. </summary>
    public class Envelope: Dime
    {
        #region -- PUBLIC --
        ///<summary>The cryptographic profile version used for this envelope.</summary>
        public new ProfileVersion Profile { get { return base.Profile; } set { Reset(); base.Profile = value; } }
        /// <summary>The identity of the issuer, and thus sealer (signer), of the enveloper.</summary>
        public Identity Identity { get { return this._identity; } set { this.Reset(); this._identity = value; } }
        /// <summary>A unique identity for the envelope. If an envelope is modfied after it has been sealed, then this id changes.</summary>
        public Guid Id { get { return this._claims.uid; } }
        /// <summary>A list of messages kept inside the envelope.</summary>
        public List<Message> Messages { get; private set; }
        /// <summary>The id of the receiver.</summary>
        public Guid SubjectId { get { return this._claims.sub; } set { this.Reset(); this._claims.sub = value; } }
        /// <summary>The id of the issuer (subject id of the issuer).</summary>
        public Guid IssuerId { get { return this._claims.iss; } set { this.Reset(); this._claims.iss = value; } }
        /// <summary>The timestamp of when the envelope was created (issued).</summary>
        public long IssuedAt { get { return this._claims.iat; } set { this.Reset(); this._claims.iat = value; } }
        /// <summary>The timestamp of when the envelope is expired and is no longer valid.</summary>
        public long ExpiresAt { get { return this._claims.exp; } set { this.Reset(); this._claims.exp = value; } }

        public Envelope() { }

        /// <summar>Constructs a new Envelope object from the provided parameters. The envelope will be valid from the time of creation until
        /// the seconds set in 'validFor' have passed.</summary>
        /// <param name="issuerIdentity">The identity of the issuer.</param>
        /// <param name="subjectId">The id of the receiving subject.</param>
        /// <param name="validFor">The number of seconds before the envelope expires.</param>
        /// <param name="profile">The cryptographic profile version to use (optional)</param>
        public Envelope(Identity issuerIdentity, Guid subjectId, long validFor, ProfileVersion profile = Crypto.DEFUALT_PROFILE)
        {
            this._identity = issuerIdentity;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            this._claims = new EnvelopeClaims(Guid.NewGuid(), subjectId, issuerIdentity.SubjectId, now, (now + validFor));
            this.Profile = profile;
        }
        
        /// <summary>This will seal an envelope by signing it using the provided private key (of key type 'Identity').
        /// The provided private key must be associated with the public key in the 'Idenity' object inside the envelope
        /// object to be signed. If not, then the envelope will not be trusted by the receiving party.</summary>
        /// <param name="privateKey">The private key that should be used to sign the envelope.</param>
        /// <exception cref="ArgumentNullException">If the passed private key is null.</exception> 
        /// <exception cref="DataFormatException">If required data is missing in the envelope.</exception> 
        /// <exception cref="UnsupportedProfileException">If an invalid cryptographic profile version is set.</exception>
        /// <exception cref="DateExpirationException">If 'IssuedAt' and/or 'ExpiresAt' contain invalid values, or the message has expired.</exception>
        public override void Seal(string privateKey)
        {
            if (this.Messages == null || this.Messages.Count == 0) { throw new DataFormatException("No messages added to the envelope."); } 
            base.Seal(privateKey);
        }

        /// <summary>Adds a message to the envelope. Call to this function will reset the envelope and it
        /// needs to be sealed again. Messages must have been sealed before being added to an envelope.</summary>
        /// <param name="message">The message object to add to the envelope</param>
        /// <exception cref="IntegrityException">If the message added is not first sealed.</exception>
        public void AddMessage(Message message)
        {
            if (!message.IsSealed) { throw new IntegrityException("Message must be sealed before being added to an envelope."); }
            Reset();
            if (this.Messages == null) { this.Messages = new List<Message>(); }
            this.Messages.Add(message);            
        }

        /// <summary>Will remove all messages in the envelope. Call to this function will reset the envelope and it
        /// needs to be sealed again.</summary>
        public void RemoveAllMessages()
        {
            Reset();
            this.Messages = null;
        }

        public override void Verify() { Verify(false); }

        /// <summary>Will verify the data in the fields in the evelope object. It will also verify all underlaying
        /// objects if 'shallowVerification' is set to true (or omitted). The signature of the envelope object will
        /// be verified with the public key from the 'Identity.TrustedIdentity' property.</summary>
        /// <param name="shallowVerification">Indicate if a deep verification of all encapsulated objects should be skipped.</param>
        /// <exception cref="UnsupportedProfileException">If an invalid cryptographic profile version is set.</exception>
        /// <exception cref="DateExpirationException">If 'IssuedAt' and/or 'ExpiresAt' contain invalid values, or the envelope has expired.</exception>
        /// <exception cref="IntegrityException">If the signature failes validation, or cannot be validated.</exception>
        public void Verify(bool shallowVerification)
        {
            if (!Crypto.SupportedProfile(this.Profile)) { throw new UnsupportedProfileException("Unsupported cryptography profile version."); }
            // Verify IssuedAt and ExpiresAt
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (this.IssuedAt > now) { throw new DateExpirationException("Issuing date in the future."); }
            if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Expiration before issuing date."); }
            if (this.ExpiresAt < now) { throw new DateExpirationException("Passed expiration date."); }
            // Verify underlaying objects, if requested
            if (!shallowVerification)
            {
                this.Identity.Verify();
                foreach(Message message in this.Messages)
                {
                    Message linkedMessage = null;
                    if (message.LinkedTo != null)
                    {
                        linkedMessage = this.Messages.Find(element => message.LinkedTo.StartsWith(element.Id.ToString()));
                        message.Verify(linkedMessage);
                    }
                    else
                    {
                        message.Verify();
                    }
                    
                }
            }
            // Verify signature
            if (this._signature == null) { throw new IntegrityException("Signature missing."); }
            if (this.Identity.SubjectId != this.IssuerId) { throw new IntegrityException("Issuing identity subject id does not match issuer id of the envelope."); }
            Crypto.VerifySignature(this.Profile, Encode(), this._signature, this.Identity.IdentityKey);
        }

        #endregion

        #region -- PROTECTED --

        protected override void Populate(string encoded)
        {
            if (Dime.GetType(encoded) != typeof(Envelope)) { throw new DataFormatException("Invalid header."); }
            string[] components = encoded.Split(new char[] { Envelope._MAIN_DELIMITER });
            if (components.Length != 5) { throw new DataFormatException("Unexpected number of components found then decoding identity."); }
            ProfileVersion profile;
            Enum.TryParse<ProfileVersion>(components[0].Substring(1), true, out profile);
            this.Profile = profile;
            if (!Crypto.SupportedProfile(this.Profile)) { throw new UnsupportedProfileException("Unsupported cryptography profile."); }
            byte[] identityBytes = Utility.FromBase64(components[1]);
            this.Identity = Dime.Import<Identity>(System.Text.Encoding.UTF8.GetString(identityBytes, 0, identityBytes.Length));
            this._claims = JsonSerializer.Deserialize<EnvelopeClaims>(Utility.FromBase64(components[3]));
            byte[] msgBytes = Utility.FromBase64(components[2]);
            string[] msgArray = System.Text.Encoding.UTF8.GetString(msgBytes, 0, msgBytes.Length).Split(new char[] { ';' });
            this.Messages = new List<Message>();
            foreach(string msg in msgArray)
            {
                Message message = Dime.Import<Message>(msg);
                this.Messages.Add(message); 
            }
            this._encoded = encoded.Substring(0, encoded.LastIndexOf(Dime._MAIN_DELIMITER));
            this._signature = components[components.Length - 1];
        }

        protected override string Encode()
        {
            if (this._encoded == null) 
            {  
                StringBuilder envBuilder = new StringBuilder();
                envBuilder.Append('E'); // This is the header of an DiME envelope
                envBuilder.Append((int)this.Profile);
                envBuilder.Append(Dime._MAIN_DELIMITER);
                envBuilder.Append(Utility.ToBase64(this.Identity.Export()));
                envBuilder.Append(Dime._MAIN_DELIMITER);
                StringBuilder msgBuilder = new StringBuilder();
                foreach (Message message in this.Messages)
                {
                    msgBuilder.AppendFormat("{0};", message.Export());
                }
                msgBuilder.Remove(msgBuilder.Length - 1, 1); 
                envBuilder.Append(Utility.ToBase64(msgBuilder.ToString()));
                envBuilder.Append(Dime._MAIN_DELIMITER);
                envBuilder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                this._encoded = envBuilder.ToString();
            }
            return this._encoded;
        }

        #endregion

        #region -- PRIVATE --

        private struct EnvelopeClaims
        {
            public Guid uid { get; set; }
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }

            [JsonConstructor]
            public EnvelopeClaims(Guid uid, Guid sub, Guid iss, long iat, long exp)
            {
                this.uid = uid;
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
            }
        }
        private EnvelopeClaims _claims;
        private Identity _identity;

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
