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
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ShiftEverywhere.DiME
{
    public class Dime
    {

        public const string HEADER = "DiME";
        public const long VALID_FOR_1_YEAR = 365 * 24 * 60 * 60; 
        ///<summary>A shared trusted identity that acts as the root identity in the trust chain.</summary>
        public static Identity TrustedIdentity { get { lock(Dime._lock) { return Dime._trustedIdentity; } } }

        public Guid? IssuerId { get { return (this._claims.HasValue) ? this._claims.Value.iss : null; } }
        public long? IssuedAt { get { return (this._claims.HasValue) ? this._claims.Value.iat : null; } }
        public string State { get { return (this._claims.HasValue) ? this._claims.Value.sta : null; } }
        
        public IList<DimeItem> Items { get { return (this._items != null) ? this._items.AsReadOnly() : null; } }

        public bool IsSealed { get { return (this._signature != null); } }
        public bool IsAnnonymous { get { return !this._claims.HasValue; } }

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

        public Dime() { }

        public Dime(Guid issuerId, string state = null)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            this._claims = new _DimeClaims(issuerId, now, state);
        }

        public static Dime Import(string exported)
        {
            if (!exported.StartsWith(Dime.HEADER)) { throw new FormatException("Not a Dime object, invalid header."); }
            string[] sections = exported.Split(Dime._SECTION_DELIMITER);
            // 0: HEADER
            string[] components = sections[0].Split(Dime._COMPONENT_DELIMITER);
            Dime dime;
            if (components.Length == 2)
            {
                _DimeClaims claims = JsonSerializer.Deserialize<_DimeClaims>(Utility.FromBase64(components[1]));
                dime = new Dime(claims);
            }
            else if (components.Length == 1) 
                dime = new Dime();
            else 
                throw new FormatException($"Not a valid Dime object, unexpected number of components in header, got: '{components.Length}', expexted: '1' or '2'");
            // 1 to LAST or LAST - 1 
            int endIndex = (dime.IsAnnonymous) ? sections.Length : sections.Length - 1; // end index dependent on unsealed, annonymous Dime or not
            List<DimeItem> items = new List<DimeItem>(endIndex - 1);
            for (int index = 1; index < endIndex; index++)
            {
                string iid = sections[index].Substring(0, sections[index].IndexOf(Dime._COMPONENT_DELIMITER));
                items.Add(DimeItem.FromString(sections[index]));
            }
            dime._items = items;
            dime._encoded = exported.Substring(0, exported.LastIndexOf(Dime._SECTION_DELIMITER));
            if (!dime.IsAnnonymous)
                dime._signature = sections.Last(); 
            return dime;
        }

        public Dime AddItem(DimeItem item)
        {
            if (this._signature != null) { throw new IntegrityException("Unable to modify Dime after sealing."); }
            if (this._items == null)
                this._items = new List<DimeItem>();
            this._items.Add(item);
            return this;
        }

        public Dime SetItems(List<DimeItem> items)
        {
            if (this._signature != null) { throw new IntegrityException("Unable to modify Dime after sealing."); }
            this._items = items.ToList();
            return this;
        }

        public Dime Seal(KeyBox keybox)
        {
            if (this.IsAnnonymous) { throw new FormatException("Cannot seal an annonymous Dime."); }
            if (this._signature != null) { throw new FormatException("Dime already sealed."); }
            if (this._items == null || this._items.Count == 0) { throw new FormatException("At least one item must be attached before sealing Dime."); }
            this._signature = Crypto.GenerateSignature(Encode(), keybox);
            return this;
        }

        public Dime Verify(KeyBox keybox)
        {
            if (this.IsAnnonymous) { throw new FormatException("Annonymous Dime, unable to verify."); }
            if (this._signature == null) { throw new IntegrityException("Dime is not sealed."); }
            Crypto.VerifySignature(Encode(), this._signature, keybox);
            return this;
        }

        public string Export()
        {
            if (!this.IsAnnonymous)
            {
                if (this._signature == null) { throw new FormatException("Dime must be sealed before exporting."); }
                return $"{Encode()}{Dime._SECTION_DELIMITER}{this._signature}";
            }
            else
                return Encode();
        }

        public string Thumbprint()
        {
            return Crypto.GenerateHash(ProfileVersion.One, this.Encode());
        }

        internal const char _COMPONENT_DELIMITER = '.';
        internal const char _ARRAY_ITEM_DELIMITER = ';'; // TODO: check if it is used... ??
        internal const char _SECTION_DELIMITER = ':';

        #region -- PRIVATE --

        private static readonly object _lock = new object();
        private static Identity _trustedIdentity;
        private List<DimeItem> _items;
        private string _encoded;
        private string _signature;
        private _DimeClaims? _claims;

        private struct _DimeClaims
        {
            public Guid iss { get; set; }
            public long iat { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string sta { get; set; }

            [JsonConstructor]
            public _DimeClaims(Guid iss, long iat, string sta)
            {
                this.iss = iss;
                this.iat = iat;
                this.sta = sta;
            }

        }

        private Dime(_DimeClaims claims)
        {
            this._claims = claims;
        }

        private string Encode()
        {
            if (this._encoded == null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(Dime.HEADER);
                if (!this.IsAnnonymous)
                {
                    builder.Append(Dime._COMPONENT_DELIMITER);
                    builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                }
                foreach(DimeItem item in this._items)
                {
                    builder.Append(Dime._SECTION_DELIMITER);
                    builder.Append(item.ToString());
                }
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

    }

}

