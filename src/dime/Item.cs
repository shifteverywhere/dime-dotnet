//
//  Item.cs
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Linq;

namespace ShiftEverywhere.DiME
{
    public abstract class Item 
    {
        #region -- PUBLIC -- 

        public abstract string Tag { get; }

        public abstract Guid UniqueId { get; }

        public bool IsSigned => this.Signature != null;

        public static T Import<T>(string exported) where T: Item, new()
        {
            var envelope = Envelope.Import(exported);
            if (envelope.Items.Count > 1) { throw new FormatException("Multiple items found, import as 'Envelope' instead."); }
            return (T)envelope.Items.First();
        }

        public string Export()
        {
            var envelope = new Envelope();
            envelope.AddItem(this);
            return envelope.Export();
        }

        public static Item FromEncoded(string encoded)
        {
            var t = TypeFromTag(encoded[..encoded.IndexOf(Envelope._COMPONENT_DELIMITER)]);
            var item = (Item)Activator.CreateInstance(t);
            if (item == null) return null;
            item.Decode(encoded);
            return item;
        }
        
        public virtual void Sign(Key key)
        {
            if (IsSigned) { throw new InvalidOperationException("Unable to sign item, it is already signed."); }
            if (key == null || key.Secret == null) { throw new ArgumentNullException(nameof(key), "Unable to sign item, key for signing must not be null."); }
            Signature = Crypto.GenerateSignature(Encode(), key);
        }

        public string Thumbprint()
        {
            return Thumbprint(ToEncoded());
        }

        public static string Thumbprint(string encoded)
        {
            return Utility.ToHex(Crypto.GenerateHash(encoded));
        }

        public virtual string ToEncoded()
        {
            return IsSigned ? $"{Encode()}{Envelope._COMPONENT_DELIMITER}{Signature}" : Encode();
        }
        
        public void Verify(string publicKey)
        {
            Verify(new Key(publicKey));
        }

        public virtual void Verify(Key key)
        {
            if (!IsSigned) { throw new InvalidOperationException("Unable to verify, item is not signed."); }
            Crypto.VerifySignature(Encode(), Signature, key);
        }

        #endregion

        #region -- PROTECTED --

        protected string Encoded;
        protected string Signature;

        protected abstract void Decode(string encoded);

        protected abstract string Encode();

        protected void ThrowIfSigned() {
            if (IsSigned) { throw new InvalidOperationException("Unable to complete operation, Di:ME item already signed."); }
        }

        #endregion

        #region -- PRIVATE --
        
        private static Type TypeFromTag(string tag)
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