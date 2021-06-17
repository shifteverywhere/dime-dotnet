//
//  KeyList.cs
//  DiME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Collections.Generic;

namespace ShiftEverywhere.DiME
{
    public class KeyList: Dime, IAttached
    {
        #region -- PUBLIC --

        public const string ITID = "aW8uZGltZWZvcm1hdC5reWw"; // base64 of io.dimeformat.kyl
        public override Guid Id { get { return this._claims.uid; } }
        public Guid? AudienceId { get { return this._claims.aud; } }
        public long IssuedAt { get { return this._claims.iat; } }
        public long? ExpiresAt { get { return this._claims.exp; } }
        public Identity Issuer { get; private set; }
        public IList<KeyBox> Keys { get; private set; }
        public bool IsSealed { get { return (this._signature != null); } }

        public KeyList() { }

        public KeyList(Identity issuer, List<KeyBox> keys, Guid? audienceId = null, long? validFor = null)
        {
            if (issuer == null) { throw new ArgumentNullException(nameof(issuer), "Issuer (sender) identity must not be null."); }
            if (keys == null || keys.Count == 0) { throw new ArgumentNullException(nameof(keys), "Must provide atleast 1 key."); }
            long iat = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long? exp = (validFor.HasValue && validFor.Value > 0) ? iat + validFor.Value : null; 
            this.Issuer = issuer;
            this.Keys = keys.AsReadOnly();
            this._claims = new KeyListClaims(Guid.NewGuid(), audienceId, issuer.SubjectId, iat, exp);
            this.Profile = issuer.Profile;
        }

        public KeyList Seal(string privateKey, bool includeKey = true)
        {
            if (this._signature == null)
            {
                if (privateKey == null) { throw new ArgumentNullException(nameof(privateKey), "Private key for signing cannot be null."); }
                if (this.Keys == null || this.Keys.Count == 0) { throw new DataFormatException("Unable to seal message, no keys added."); }
                this._includeKey = includeKey;
                this._signature = Crypto.GenerateSignature(this.Issuer.Profile, Encoded(), privateKey);
            }
            return this;
        }

        public void Verify() { 
            if (!Crypto.SupportedProfile(this.Profile)) { throw new UnsupportedProfileException("Unsupported cryptography profile version."); }
            if (this.Keys == null || this.Keys.Count == 0) { throw new DataFormatException("No keys added to key list."); }
            // Verify IssuedAt and ExpiresAt
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            if (this.IssuedAt > now) { throw new DateExpirationException("Issuing date in the future."); }
            if (this.ExpiresAt.HasValue)
            {
                if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Expiration before issuing date."); }
                if (this.ExpiresAt < now) { throw new DateExpirationException("Passed expiration date."); }
            }
            this.Issuer.Verify();
            Crypto.VerifySignature(this.Issuer.Profile, Encoded(), this._signature, this.Issuer.IdentityKey);
         }

        #endregion

        #region -- INTERNAL --

        internal override void Populate(Identity issuer, string encoded)
        {
            this.Issuer = issuer;
            this.Profile = this.Issuer.Profile;
            string[] components = encoded.Split(new char[] { Dime._COMPONENT_DELIMITER });
            if (components.Length != KeyList._NBR_EXPECTED_COMPONENTS) { throw new DataFormatException($"Unexpected number of components for identity issuing request, expected {KeyList._NBR_EXPECTED_COMPONENTS}, got {components.Length}."); }
            if (components[KeyList._IDENTIFIER_INDEX] != KeyList.ITID) { throw new DataFormatException($"Unexpected object identifier, expected: \"{KeyList.ITID}\", got \"{components[KeyList._IDENTIFIER_INDEX]}\"."); }
            this._claims = JsonSerializer.Deserialize<KeyListClaims>(Utility.FromBase64(components[KeyList._CLAIMS_INDEX]));
            byte[] keysBytes = Utility.FromBase64(components[KeyList._KEYS_INDEX]);
            string[] keys = System.Text.Encoding.UTF8.GetString(keysBytes, 0, keysBytes.Length).Split(Dime._ARRAY_ITEM_DELIMITER);
            if (keys == null || keys.Length == 0) { throw new DataFormatException("No keys found in key list object."); }
            List<KeyBox> list = new List<KeyBox>();
            foreach(string key in keys)
            {
                list.Add(Dime.Import<KeyBox>(key));
            }
            this.Keys = list.AsReadOnly();
        }

        internal override string Encoded(bool includeSignature = false)
        {
            if (this._encoded == null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(this.Issuer.Encoded(true));
                builder.Append(Dime._SECTION_DELIMITER);
                builder.Append(KeyList.ITID);
                builder.Append(Dime._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                builder.Append(Dime._COMPONENT_DELIMITER);
                int count = this.Keys.Count;
                StringBuilder keysBuilder = new StringBuilder();
                foreach(KeyBox key in this.Keys)
                {
                    keysBuilder.Append(key.Encoded(this._includeKey, false));
                    if (--count != 0)
                    {
                        keysBuilder.Append(Dime._ARRAY_ITEM_DELIMITER);
                    }
                }
                builder.Append(Utility.ToBase64(keysBuilder.ToString()));
                this._encoded = builder.ToString();
            }
            if (includeSignature && !this.IsSealed) { throw new IntegrityException("Message is not sealed, cannot be exported."); }
            return (includeSignature) ? $"{this._encoded}{Dime._COMPONENT_DELIMITER}{this._signature}" : this._encoded;
        }

        #endregion

        # region -- PROTECTED --
       
        protected override void FixateEncoded(string encoded)
        {
            this._encoded = encoded.Substring(0, encoded.LastIndexOf(Dime._COMPONENT_DELIMITER));
            this._signature = encoded.Substring(encoded.LastIndexOf(Dime._COMPONENT_DELIMITER) + 1);
        }

        #endregion

        #region -- PRIVATE --

        private const int _NBR_EXPECTED_COMPONENTS = 4;
        private const int _IDENTIFIER_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;
        private const int _KEYS_INDEX = 2;
        private string _encoded;
        private string _signature;
        private KeyListClaims _claims;
        private bool _includeKey = true;

        private struct KeyListClaims
        {
            public Guid uid { get; set; }
             [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public Guid? aud { get; set; }
            public Guid iss { get; set; }
            public long iat { get; set; }
             [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public long? exp { get; set; }

            [JsonConstructor]
            public KeyListClaims(Guid uid, Guid? aud, Guid iss, long iat, long? exp = null)
            {
                this.uid = uid;
                this.aud = aud;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
            }
        }

        #endregion

    }

}