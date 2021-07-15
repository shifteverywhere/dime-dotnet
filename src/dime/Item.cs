//
//  Item.cs
//  DiME - Digital Identity Message Envelope
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

        public abstract string ItemIdentifier { get; }

        public abstract Guid UID { get; }

        public bool IsSealed { get { return (this._signature != null); } }

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

        internal static Item FromEncoded(string encoded)
        {
            Type t = Item.TypeFromIID(encoded.Substring(0, encoded.IndexOf(Envelope._COMPONENT_DELIMITER)));
            Item item = (Item)Activator.CreateInstance(t);
            item.Decode(encoded);
            return item;
        }
        
        public virtual void Seal(KeyBox keybox)
        {
            if (this.IsSealed) { throw new IntegrityException("Dime item already sealed."); }
            if (keybox == null || keybox.Key == null) { throw new ArgumentNullException(nameof(keybox), "Key for sealing cannot be null."); }
            this._signature = Crypto.GenerateSignature(Encode(), keybox);
        }

        public string Thumbprint(Profile profile = Profile.Uno)
        {
            return Crypto.GenerateHash(profile, this.Encode());
        }

        internal virtual string ToEncoded() {
            if (this.IsSealed)
            {
                return $"{Encode()}{Envelope._COMPONENT_DELIMITER}{this._signature}";
            }
            return Encode();
        }

        public static Type TypeFromIID(string iid)
        {
            switch (iid) {
                case Identity.IID: return typeof(Identity);
                case IdentityIssuingRequest.IID: return typeof(IdentityIssuingRequest);
                case Message.IID: return typeof(Message);
                case KeyBox.IID: return typeof(KeyBox);
                default: return null;
            }
        }

        public virtual void Verify(KeyBox keybox)
        {
            if (!this.IsSealed) { throw new IntegrityException("Dime item not sealed."); }
            Crypto.VerifySignature(Encode(), this._signature, keybox);
        }

        #endregion

        #region -- PROTECTED --

        protected string _encoded;
        protected string _signature;

        protected abstract void Decode(string encoded);

        protected abstract string Encode();

        #endregion

    }

}