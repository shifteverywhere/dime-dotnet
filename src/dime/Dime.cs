//
//  Dime.cs
//  DiME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;

namespace ShiftEverywhere.DiME
{
    ///<summary>An abstract base class for all DiME based objects.</summary>
    public abstract class Dime
    {
        #region -- PUBLIC --

        public const string DIME_HEADER = "DI";

        ///<summary>A shared trusted identity that acts as the root identity in the trust chain.</summary>
        public static Identity TrustedIdentity { get { lock(Dime._lock) { return Dime._trustedIdentity; } } }
        /// <summary>The cryptography profile version that is used within the object.</summary>
        public ProfileVersion Profile { get; protected set; }
        /// <summary>Indicates if the object is sealed or not (signed).</summary>
        public bool IsSealed { get { return (this._signature != null && this._signature.Length > 0); } }
        /// <summary>Indicates if the object can be sealed or not (signed).</summary>
        public bool Sealable { get; protected set; } = true;

        ///<summary>Creates an object from an encoded DiME string.</summary>
        ///<param name="encoded">The encoded DiME string to decode.</param>
        ///<returns>An initialized DiME object.</returns>
        public static T Import<T>(string encoded) where T: Dime, new()
        {
            if (!encoded.StartsWith(Dime.DIME_HEADER)) { throw new DataFormatException("Invalid header."); }
            T dime = new T();
            ProfileVersion profile;
            Enum.TryParse<ProfileVersion>(encoded.Substring(Dime.DIME_HEADER.Length, 1), true, out profile);
            Crypto.SupportedProfile(profile);
            dime.Profile = profile;
            string encodedObject = (dime.Sealable) ? encoded.Substring(0, encoded.LastIndexOf(Dime._COMPONENT_DELIMITER)) : encoded;
            dime.Populate(encodedObject.Substring(encodedObject.IndexOf(Dime._COMPONENT_DELIMITER)+ 1));
            if (dime.Sealable)
            {
                dime._signature = encoded.Substring(encoded.LastIndexOf(Dime._COMPONENT_DELIMITER) + 1);
            }
            dime._encoded = encodedObject;
            return dime;
        }

        ///<summary>Gets the type of DiME object stored as an encoded string.</summary>
        ///<param name="encoded">The encoded DiME string to check.</param>
        ///<returns>The type of the object encoded.</returns>
        public static Type GetType(string encoded)
        {
            char header = char.Parse(encoded.Substring(0, 1));
            switch(header)
            {
                case 'I': return typeof(Identity);
                case 'M': return typeof(Message);
                case 'E': return typeof(Envelope);
                case 'i': return typeof(IdentityIssuingRequest);
                case 'k': return typeof(KeyBox);
                case 'a': return typeof(Attachment);
                default: return null;
            }
        }

        ///<summary>Exports an object into an encoded DiME string.</summary>
        ///<returns>An encoded DiME string.</returns>
        public virtual string Export() 
        {
            if (this.Sealable && !this.IsSealed) { throw new IntegrityException("Signature missing."); }
            if (this._signature != null)
            {
                return $"{this.Encoded}{Dime._COMPONENT_DELIMITER}{this._signature}";
            }
            return this.Encoded;
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
        public virtual void Seal(string privateKey)
        {
            if (!this.Sealable) { throw new IntegrityException("Object is not sealable."); }
            if (!this.IsSealed)
            {
                if (privateKey == null) { throw new ArgumentNullException(nameof(privateKey), "Private key for signing cannot be null."); }
                this._signature = Crypto.GenerateSignature(this.Profile, this.Encoded, privateKey);
            }
        }

        /// <summary>Generates a cryptographically unique thumbprint of the DiME object.</summary>
        /// <returns>An unique thumbprint.</returns>
        public virtual string Thumbprint()
        {
            return Crypto.GenerateHash(this.Profile, this.Encoded);
        }

        ///<summary>Set the shared trusted identity, which forms the basis of the trust chain. All identities will be verified
        /// from a trust perspecitve using this identity. For the trust chain to hold, then all identities must be either issued
        /// by this identity or other identities (with the 'issue' capability) that has been issued by this identity.
        ///<param name="identity">The identity to set as the trusted identity.</param>
        public static void SetTrustedIdentity(Identity identity)
        {
            lock(Dime._lock)
            {
                Dime._trustedIdentity = identity;
            }
        }

        /// <summary>Will verify the object, including the integrity of the data and any relevant fields.</summary>
        public abstract void Verify();

        #endregion

        #region -- PROTECTED --

        protected Dime() { }
        protected abstract void Populate(string encoded);

        protected virtual void Verify(string publicKey)
        {
            if (this._signature == null || this._signature.Length == 0) { throw new IntegrityException("Signature missing"); }
            Crypto.VerifySignature(this.Profile, this.Encoded, this._signature, publicKey);
        }

        protected const char _COMPONENT_DELIMITER = '.';
        protected const char _ARRAY_ITEM_DELIMITER = ';';
        protected const char _ATTATCHMENT_DELIMITER = ':';
        
        protected string Encoded 
        { 
            get 
            { 
                if (this._encoded == null)
                {
                    StringBuilder builder = new StringBuilder();
                    builder.Append(Dime.DIME_HEADER);
                    builder.Append((int)this.Profile);
                    builder.Append(Dime._COMPONENT_DELIMITER);
                    Encode(builder);
                    this._encoded = builder.ToString();
                }
                return this._encoded;
            } 
        }

        protected abstract void Encode(StringBuilder builder);

        protected virtual bool Unseal()
        {
            if (this.IsSealed) {
                this._encoded = null;
                this._signature = null;
                return true;
            }
            return false;
        }

        #endregion

        #region -- PRIVATE --

        private static readonly object _lock = new object();
        private static Identity _trustedIdentity;
        private string _encoded;
        private string _signature;

        #endregion 

    }
}