using System;
using System.Text;
using System.Text.Json;
using System.Collections.Generic;

namespace ShiftEverywhere.DiME
{
    ///<summary>Acts as a container object for Message instances. Several messages, independent on their origin
    /// may be added to an envelope. The entity that created the envelope signs it before exporting and thus sealing
    /// it's content. </summary>
    public class Envelope
    {
        #region -- PUBLIC --
        ///<summary>The cryptographic profile version used for this envelope.</summary>
        public int Profile { get { return this._profile; } set { this.Reset(); this._profile = value; } }
        /// <summary>The identity of the issuer, and thus sealer (signer), of the enveloper.</summary>
        public Identity Identity { get { return this._identity; } set { this.Reset(); this._identity = value; } }
        /// <summary>A unique identity for the envelope. If an envelope is modfied after it has been sealed, then this id changes.</summary>
        public Guid Id { get { return this._data.uid; } }
        /// <summary>A list of messages kept inside the envelope.</summary>
        public List<Message> Messages { get; private set; }
        /// <summary>The id of the receiver.</summary>
        public Guid SubjectId { get { return this._data.sub; } set { this.Reset(); this._data.sub = value; } }
        /// <summary>The id of the issuer (subject id of the issuer).</summary>
        public Guid IssuerId { get { return this._data.iss; } set { this.Reset(); this._data.iss = value; } }
        /// <summary>The timestamp of when the envelope was created (issued).</summary>
        public long IssuedAt { get { return this._data.iat; } set { this.Reset(); this._data.iat = value; } }
        /// <summary>The timestamp of when the envelope is expired and is no longer valid.</summary>
        public long ExpiresAt { get { return this._data.exp; } set { this.Reset(); this._data.exp = value; } }
        /// <summary>Indicates if the envelope is sealed or not (signed).</summary>
        public bool IsSealed { get { return this._signature != null; } }

        /// <summar>Constructs a new Envelope object from the provided parameters. The envelope will be valid from the time of creation until
        /// the seconds set in 'validFor' have passed.</summary>
        /// <param name="issuerIdentity">The identity of the issuer.</param>
        /// <param name="subjectId">The id of the receiving subject.</param>
        /// <param name="validFor">The number of seconds before the envelope expires.</param>
        /// <param name="profile">The cryptographic profile version to use (optional)</param>
        public Envelope(Identity issuerIdentity, Guid subjectId, long validFor, int profile = Crypto.DEFUALT_PROFILE)
        {
            this._identity = issuerIdentity;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            this._data = new InternalData(Guid.NewGuid(), subjectId, issuerIdentity.SubjectId, now, (now + validFor));
            this._profile = profile;
        }

        /// <summary>Creates an envelope object from a DiME encoded string. It will also verify field values and
        /// signatures before returning a new instance.</summary>
        /// <param name="encoded">The DiME encoded envelope string to import.</param>
        /// <exception cref="DataFormatException">If the format of the encoded string is invalid.</exception>
        /// <exception cref="UnsupportedProfileException">If an invalid cryptographic profile version is set.</exception>
        /// <exception cref="DateExpirationException">If 'IssuedAt' and/or 'ExpiresAt' contain invalid values, or the envelope has expired.</exception>
        /// <exception cref="IntegrityException">If the signature failes validation, or cannot be validated.</exception>
        /// <returns>An initialized and verified Envelope object.</returns>
        public static Envelope Import(string encoded)
        {
            if (!Envelope.IsEnvelope(encoded)) { throw new DataFormatException("Unexpected data format."); }
            string[] components = encoded.Split(new char[] { '.' });
            if (components.Length != 5) { throw new DataFormatException("Unexpected number of components found then decoding identity."); }
            int profile = int.Parse(components[0].Substring(1));
            byte[] identityBytes = Utility.FromBase64(components[1]);
            Identity identity = Identity.Import(System.Text.Encoding.UTF8.GetString(identityBytes, 0, identityBytes.Length));
            string envPart = encoded.Substring(0, encoded.LastIndexOf('.'));
            string signature = components[components.Length - 1];
            Envelope.InternalData parameters = JsonSerializer.Deserialize<Envelope.InternalData>(Utility.FromBase64(components[3]));
            Envelope envelope = new Envelope(identity, parameters, profile);
            byte[] msgBytes = Utility.FromBase64(components[2]);
            string[] msgArray = System.Text.Encoding.UTF8.GetString(msgBytes, 0, msgBytes.Length).Split(new char[] { ';' }); ;
            envelope.Messages = new List<Message>();
            foreach(string msg in msgArray)
            {
                Message message = Message.Import(msg);
                envelope.Messages.Add(message); 
            }
            envelope._encoded = envPart;
            envelope._signature = signature;
            envelope.Verify();
            return envelope;
        }

        /// <summary>This function encodes and exports the envelope object in the DiME format. It will verify 
        /// the data inside the envelope, as well as the signature attached.</summary>
        /// <exception cref="IntegrityException">If the signature failes validation, or cannot be validated.</exception>
        /// <returns>A DiME encoded string.</returns>
        public string Export()
        {
            if (!this.IsSealed) { throw new IntegrityException("Signature missing, unable to export."); }
            StringBuilder sb = new StringBuilder();
            sb.Append(Encode());
            sb.Append(_delimiter);
            sb.Append(_signature);
            return sb.ToString();
        }
        
        /// <summary>This will seal an envelope by signing it using the provided private key (of key type 'Identity').
        /// The provided private key must be associated with the public key in the 'Idenity' object inside the envelope
        /// object to be signed. If not, then the envelope will not be trusted by the receiving party.</summary>
        /// <param name="identityPrivateKey">The private key that should be used to sign the envelope.</param>
        /// <exception cref="ArgumentNullException">If the passed private key is null.</exception> 
        /// <exception cref="ArgumentException">If required data is missing in the envelope.</exception> 
        /// <exception cref="UnsupportedProfileException">If an invalid cryptographic profile version is set.</exception>
        /// <exception cref="DateExpirationException">If 'IssuedAt' and/or 'ExpiresAt' contain invalid values, or the message has expired.</exception>
        public void Seal(string identityPrivateKey)
        {
            if (this._signature == null)
            {
                if (identityPrivateKey == null) { throw new ArgumentNullException("Private key for signing cannot be null.", "identityPrivateKey"); }
                if (this.Messages == null || this.Messages.Count == 0) { throw new ArgumentException("No messages added to the envelope.", "Messages"); } 
                this._signature = Crypto.GenerateSignature(this.Profile, Encode(), identityPrivateKey);
                Verify();
            }
        }

        /// <summary>Helper function to quickly check if a string is potentially a DiME encoded envelope object.</summary>
        /// <param name="encoded">The string to validate.</param>
        /// <returns>An indication if the string is a DiME encoded envelope.</returns>
        public static bool IsEnvelope(string encoded)
        {
            return encoded.StartsWith(Envelope._HEADER);
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

        /// <summary>Will verify the data in the fields in the evelope object. It will also verify all underlaying
        /// objects if 'shallowVerification' is set to true (or omitted). The signature of the envelope object will
        /// be verified with the public key from the 'Identity.TrustedIdentity' property.</summary>
        /// <param name="shallowVerification">Indicate if a deep verification of all encapsulated objects should be skipped.</param>
        /// <exception cref="UnsupportedProfileException">If an invalid cryptographic profile version is set.</exception>
        /// <exception cref="DateExpirationException">If 'IssuedAt' and/or 'ExpiresAt' contain invalid values, or the envelope has expired.</exception>
        /// <exception cref="IntegrityException">If the signature failes validation, or cannot be validated.</exception>
        public void Verify(bool shallowVerification = false)
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
                this.Identity.VerifyTrust();
                foreach(Message message in this.Messages)
                {
                    Message linkedMessage = null;
                    if (message.LinkedTo != null)
                    {
                        linkedMessage = this.Messages.Find(element => message.LinkedTo.StartsWith(element.Id.ToString()));
                    }
                    message.Verify(linkedMessage);
                }
            }
            // Verify signature
            if (this._signature == null) { throw new IntegrityException("Signature missing."); }
            if (this.Identity.SubjectId != this.IssuerId) { throw new IntegrityException("Issuing identity subject id does not match issuer id of the envelope."); }
            Crypto.VerifySignature(this.Profile, Encode(), this._signature, this.Identity.IdentityKey);
        }

        /// <summary>Generates a cryptographically unique thumbprint of the envelope.</summary>
        /// <exception cref="IntegrityException">If message is not sealed (signed).</exception> 
        /// <returns>An unique thumbprint.</returns>
        public string Thumbprint() 
        {
            if(!this.IsSealed) { throw new IntegrityException("Message not sealed."); }
            return Crypto.GenerateHash(this.Profile, Encode());
        }
        #endregion
        #region -- PRIVATE --

        private const string _HEADER = "E";
        private int _profile;
        private Identity _identity;
        private string _signature;
        private string _encoded;
        private const string _delimiter = ".";

        private struct InternalData
        {
            public Guid uid { get; set; }
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
            public long exp { get; set; }

            public InternalData(Guid uid, Guid sub, Guid iss, long iat, long exp)
            {
                this.uid = uid;
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
            }
        }
        private Envelope.InternalData _data;

        private Envelope(Identity issuerIdentity, Envelope.InternalData parameters, int profile = Crypto.DEFUALT_PROFILE)
        {
            this._identity = issuerIdentity;
            this._data = parameters;
            this._profile = profile;
        }

        private string Encode()
        {
            if (this._encoded == null) 
            {  
                // TODO: verify all values (messages == null ??)
                var envBuilder = new StringBuilder();
                envBuilder.AppendFormat("{0}{1}.{2}.", 
                                    Envelope._HEADER,
                                    this.Profile,
                                    Utility.ToBase64(this.Identity.Export()));
                var msgBuilder = new StringBuilder();
                foreach (Message message in this.Messages)
                {
                    msgBuilder.AppendFormat("{0};", message.Export());
                }
                msgBuilder.Remove(msgBuilder.Length - 1, 1); 
                envBuilder.AppendFormat("{0}.{1}",
                                        Utility.ToBase64(msgBuilder.ToString()),
                                        Utility.ToBase64(JsonSerializer.Serialize(this._data)));
                this._encoded = envBuilder.ToString();
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
