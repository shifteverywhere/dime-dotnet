//
//  Item.cs
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Linq;

#nullable enable
namespace DiME
{
    /// <summary>
    /// Base class for any other type of Di:ME items that can be included inside an Envelope instance.
    /// </summary>
    public abstract class Item 
    {
        #region -- PUBLIC -- 

        /// <summary>
        /// Returns the tag of the Di:ME item. Must be overridden by any subclass.
        /// </summary>
        public abstract string Tag { get; }

        /// <summary>
        /// Returns a unique identifier for the instance. This will be generated at instance creation.
        /// </summary>
        public abstract Guid UniqueId { get; }

        /// <summary>
        /// Checks if the item has been signed or not.
        /// </summary>
        public bool IsSigned => Signature != null;

        /// <summary>
        /// Will import an item from a DiME encoded string. Di:ME envelopes cannot be imported using this method, for
        /// envelopes use Envelope.importFromEncoded(String) instead.
        /// </summary>
        /// <param name="exported">The Di:ME encoded string to import an item from.</param>
        /// <typeparam name="T">The subclass of item of the imported Di:ME item.</typeparam>
        /// <returns>The imported Di:ME item.</returns>
        /// <exception cref="FormatException">If the encoded string is of a Di:ME envelope.</exception>
        public static T Import<T>(string exported) where T: Item, new()
        {
            var envelope = Envelope.Import(exported);
            if (envelope.Items is {Count: > 1}) { throw new FormatException("Multiple items found, import as 'Envelope' instead."); }
            if (envelope.Items != null) return (T) envelope.Items.First();
            throw new NullReferenceException("Unable to import item, unexpected error occurred.");
        }

        /// <summary>
        /// Exports the item to a Di:ME encoded string.
        /// </summary>
        /// <returns>The Di:ME encoded representation of the item.</returns>
        public string Export()
        {
            var envelope = new Envelope();
            envelope.AddItem(this);
            return envelope.Export();
        }
        
        /// <summary>
        /// Will sign an item with the proved key. The Key instance must contain a secret key and be of type IDENTITY.
        /// </summary>
        /// <param name="key">The key to sign the item with, must be of type IDENTITY.</param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public virtual void Sign(Key key)
        {
            if (IsSigned) { throw new InvalidOperationException("Unable to sign item, it is already signed."); }
            if (key.Secret == null) { throw new ArgumentNullException(nameof(key), "Unable to sign item, key for signing must not be null."); }
            Signature = Crypto.GenerateSignature(Encode(), key);
        }

        /// <summary>
        /// Returns the thumbprint of the item. This may be used to easily identify an item or detect if an item has
        /// been changed. This is created by securely hashing the item and will be unique and change as soon as any
        /// content changes.
        /// </summary>
        /// <returns>The hash of the item as a hex string.</returns>
        public string Thumbprint()
        {
            return Thumbprint(ToEncoded());
        }

        /// <summary>
        /// Returns the thumbprint of a Di:ME encoded item string. This may be used to easily identify an item or detect
        /// if an item has been changed. This is created by securely hashing the item and will be unique and change as
        /// soon as any content changes. This will generate the same value as the instance method thumbprint for the
        /// same (and unchanged) item.
        /// </summary>
        /// <param name="encoded">The Di:ME encoded item string.</param>
        /// <returns>The hash of the item as a hex string.</returns>
        public static string Thumbprint(string encoded)
        {
            return Utility.ToHex(Crypto.GenerateHash(encoded));
        }
        
        /// <summary>
        /// Verifies the signature of the item using a provided key.
        /// </summary>
        /// <param name="publicKey">The key to used to verify the signature, must not be null.</param>
        public void Verify(string publicKey)
        {
            Verify(new Key(publicKey));
        }

        /// <summary>
        /// Verifies the signature of the item using a provided key.
        /// </summary>
        /// <param name="key">The key to used to verify the signature, must not be null.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public virtual void Verify(Key key)
        {
            if (!IsSigned) { throw new InvalidOperationException("Unable to verify, item is not signed."); }
            Crypto.VerifySignature(Encode(), Signature, key);
        }

        #endregion
        
        #region -- INTERNAL --
        
        internal static Item? FromEncoded(string encoded)
        {
            var t = TypeFromTag(encoded[..encoded.IndexOf(Envelope._COMPONENT_DELIMITER)]);
            if (t == null) return null;
            var item = (Item)Activator.CreateInstance(t)!;
            item.Decode(encoded);
            return item;

        }
        
        internal virtual string ToEncoded()
        {
            return IsSigned ? $"{Encode()}{Envelope._COMPONENT_DELIMITER}{Signature}" : Encode();
        }

        #endregion
        
        #region -- PROTECTED --

        /// <summary>
        /// The encoded Di:ME item. Needs to remain intact once created or imported, this so thumbprints and signature
        /// verifications will be correct. 
        /// </summary>
        protected string? Encoded;
        /// <summary>
        /// The signature of the Di:ME item, if any. Cannot be reproduced without the private key.
        /// </summary>
        protected string? Signature;
 
        /// <summary>
        /// Decodes an item. Abstract method that needs to be implemented in any subclass.
        /// </summary>
        /// <param name="encoded"></param>
        protected abstract void Decode(string encoded);

        /// <summary>
        /// Encodes an item and stores the result in Encoded. Abstract method that needs to be implemented in any
        /// subclass.
        /// </summary>
        /// <returns></returns>
        protected abstract string Encode();

        /// <summary>
        /// Checks if the Di:ME item is signed, and if it is, will throw an exception.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the item is signed.</exception>
        protected void ThrowIfSigned() {
            if (IsSigned) { throw new InvalidOperationException("Unable to complete operation, Di:ME item already signed."); }
        }

        #endregion

        #region -- PRIVATE --
        
        private static Type? TypeFromTag(string tag)
        {
            return tag switch
            {
                Identity._TAG => typeof(Identity),
                IdentityIssuingRequest._TAG => typeof(IdentityIssuingRequest),
                Message._TAG => typeof(Message),
                Key._TAG => typeof(Key),
                _ => null
            };
        }
        
        #endregion
        
    }

}