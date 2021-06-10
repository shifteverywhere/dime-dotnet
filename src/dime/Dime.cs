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
    public abstract class Dime
    {
        #region -- PUBLIC --

        public const string HEADER = "DiME";
        public const long VALID_FOR_1_YEAR = 365 * 24 * 60 * 60; 

        ///<summary>A shared trusted identity that acts as the root identity in the trust chain.</summary>
        public static Identity TrustedIdentity { get { lock(Dime._lock) { return Dime._trustedIdentity; } } }

        public ProfileVersion Profile { get { return this._profile; } protected set { Crypto.SupportedProfile(value); this._profile = value; } }
        public abstract Guid Id { get; }
        public abstract string TypeId { get; }

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

        ///<summary>Creates an object from an encoded DiME item string.</summary>
        ///<param name="encoded">The encoded DiME item string to decode.</param>
        ///<returns>An initialized DiME item object.</returns>
        public static T Import<T>(string encoded) where T: Dime, new()
        {
            string encodedDime = (encoded.StartsWith(Dime.HEADER)) ? encoded.Substring(encoded.IndexOf(Dime._SECTION_DELIMITER) + 1) : encoded;
            T item = new T();
            item.Populate(encodedDime);
            return item;
        }

        public string Thumbprint()
        {
            return Crypto.GenerateHash(this.Profile, this.Encoded());
        }

        #endregion

        #region -- INTERNAL --

        internal const char _COMPONENT_DELIMITER = '.';
        internal const char _ARRAY_ITEM_DELIMITER = ';';
        internal const char _SECTION_DELIMITER = ':';  

        public string Export()
        {
            StringBuilder builder = new StringBuilder();
            builder.Append(Dime.HEADER);
            builder.Append(Dime._SECTION_DELIMITER);
            string encoded = this.Encoded(true);
            builder.Append(encoded);
            return builder.ToString();
        }

        internal abstract void Populate(string encoded);

        internal abstract string Encoded(bool includeSignature = false);
        
        #endregion

        #region -- PROTECTED --

        #endregion

        #region -- PRIVATE --

        private static readonly object _lock = new object();
        private static Identity _trustedIdentity;
        private ProfileVersion _profile;

        #endregion

    }

}