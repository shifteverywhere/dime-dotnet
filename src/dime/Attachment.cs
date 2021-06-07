//
//  Attachment.cs
//  DiME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Collections.Generic;

namespace ShiftEverywhere.DiME
{
    public class Attachment: Dime
    {
        #region -- PUBLIC --

        public List<byte[]> Items { get; private set; } 

        public Attachment() 
        { 
            this.Profile = Crypto.DEFUALT_PROFILE;
        }

        public override void Seal(string privateKey)
        {
            if (this.Items == null || this.Items.Count == 0) { throw new DataFormatException("No items added to attachment."); } 
            base.Seal(privateKey);
        }

        public override void Verify()
        {
            throw new NotImplementedException();
        }

        public new void Verify(string publicKey)
        {
            base.Verify(publicKey);
        }

        public void AddItem(byte[] item)
        {
            if (item != null)
            {
                Reset();
                if (this.Items == null) { this.Items = new List<byte[]>(); }
                this.Items.Add(item);
            }
        }

        public void RemoveAllItems()
        {
            Reset();
            this.Items = null;
        }

        #endregion

        #region -- PROTECTED --

        /// <summary></summary>
        protected override void Populate(string encoded)
        {
            if (Dime.GetType(encoded) != typeof(Attachment)) { throw new DataFormatException("Invalid header."); }
            string[] components = encoded.Split(new char[] { Identity._COMPONENT_DELIMITER });
            if (components.Length != 3) { throw new ArgumentException("Unexpected number of components found when decoding attachment."); }
            ProfileVersion profile;
            Enum.TryParse<ProfileVersion>(components[0].Substring(1), true, out profile);
            this.Profile = profile;
            if (!Crypto.SupportedProfile(this.Profile)) { throw new ArgumentException("Unsupported cryptography profile."); }
            byte[] itemsBytes = Utility.FromBase64(components[1]);
            string[] itemsArray = System.Text.Encoding.UTF8.GetString(itemsBytes, 0, itemsBytes.Length).Split(new char[] { Dime._ARRAY_ITEM_DELIMITER });
            this.Items = new List<byte[]>();
            foreach(string encodedItem in itemsArray)
            {
                this.Items.Add(Utility.FromBase64(encodedItem));
            }
            this._encoded = encoded.Substring(0, encoded.LastIndexOf(Dime._COMPONENT_DELIMITER));
            this._signature = components[components.Length - 1];
        }        

       protected override string Encode()
        {
              if ( this._encoded == null ) 
            {  
                StringBuilder mainBuilder = new StringBuilder();
                mainBuilder.Append('a') ;// The header of an DiME attachment
                mainBuilder.Append((int)this.Profile);
                mainBuilder.Append(Dime._COMPONENT_DELIMITER);
                StringBuilder itemsBuilder = new StringBuilder();
                foreach (byte[] item in this.Items)
                {
                    itemsBuilder.AppendFormat("{0};", Utility.ToBase64(item));
                }
                itemsBuilder.Remove(itemsBuilder.Length - 1, 1);
                mainBuilder.Append(Utility.ToBase64(itemsBuilder.ToString()));
                this._encoded = mainBuilder.ToString();
            }
            return this._encoded;
        }

        #endregion

        #region -- PRIVATE --

        private void Reset()
        {
            if (this.IsSealed)
            {
                this._encoded = null;
                this._signature = null;
            }
        }

        #endregion

    }

}