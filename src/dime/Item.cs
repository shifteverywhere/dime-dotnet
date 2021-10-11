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

        public abstract string Tag { get; }

        public abstract Guid UniqueId { get; }

        public bool IsSigned { get { return (this._signature != null); } }

        public static T Import<T>(string exported) where T: Item, new()
        {
            Envelope envelope = Envelope.Import(exported);
            if (envelope.Items.Count > 1) { throw new FormatException("Multiple items found, import as 'Envelope' instead."); }
            return (T)envelope.Items.First();
        }

        public string Export()
        {
            Envelope envelope = new Envelope();
            envelope.AddItem(this);
            return envelope.Export();
        }

        public static Item FromEncoded(string encoded)
        {
            Type t = Item.TypeFromTag(encoded.Substring(0, encoded.IndexOf(Envelope._COMPONENT_DELIMITER)));
            Item item = (Item)Activator.CreateInstance(t);
            item.Decode(encoded);
            return item;
        }
        
        public virtual void Sign(Key key)
        {
            if (this.IsSigned) { throw new InvalidOperationException("Unable to sign item, it is already signed."); }
            if (key == null || key.Secret == null) { throw new ArgumentNullException(nameof(key), "Unable to sign item, key for signing must not be null."); }
            this._signature = Crypto.GenerateSignature(Encode(), key);
        }

        public string Thumbprint(Profile profile = Profile.Uno)
        {
            return Utility.ToHex(Crypto.GenerateHash(profile, this.Encode()));
        }

        public virtual string ToEncoded() {
            if (this.IsSigned)
            {
                return $"{Encode()}{Envelope._COMPONENT_DELIMITER}{this._signature}";
            }
            return Encode();
        }

        internal static Type TypeFromTag(string iid)
        {
            switch (iid) {
                case Identity.TAG: return typeof(Identity);
                case IdentityIssuingRequest.TAG: return typeof(IdentityIssuingRequest);
                case Message.TAG: return typeof(Message);
                case Key.TAG: return typeof(Key);
                default: return null;
            }
        }

        public void Verify(string publicKey)
        {
            Verify(new Key(publicKey));
        }

        public virtual void Verify(Key keybox)
        {
            if (!this.IsSigned) { throw new InvalidOperationException("Unable to verify, item is not signed."); }
            Crypto.VerifySignature(Encode(), this._signature, keybox);
        }

        #endregion

        #region -- PROTECTED --

        protected string _encoded;
        protected string _signature;

        protected abstract void Decode(string encoded);

        protected abstract string Encode();

        protected void ThrowIfSigned() {
            if (this.IsSigned) { throw new InvalidOperationException("Unable to complete operation, Di:ME item already signed."); }
        }

        #endregion

    }

}