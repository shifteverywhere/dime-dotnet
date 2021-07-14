//
//  DimeItem.cs
//  DiME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;

namespace ShiftEverywhere.DiME
{
    public abstract class DimeItem 
    {
        #region -- PUBLIC -- 

        public abstract string ItemIdentifier { get; }

        public abstract Guid UID { get; }

        public bool IsSealed { get { return (this._signature != null); } }

        public static DimeItem FromString(string encoded)
        {
            Type t = DimeItem.TypeFromIID(encoded.Substring(0, encoded.IndexOf(Dime._COMPONENT_DELIMITER)));
            DimeItem item = (DimeItem)Activator.CreateInstance(t);
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

        public override string ToString() {
            if (this.IsSealed)
            {
                return $"{Encode()}{Dime._COMPONENT_DELIMITER}{this._signature}";
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