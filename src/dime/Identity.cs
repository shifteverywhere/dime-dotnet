//
//  Identity.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace ShiftEverywhere.DiME
{
    ///<summary>Represents a digital identity of an entity. Can be self-signed or signed by a trusted identity (and thus
    /// be part of a trust chain.</summary>
    public class Identity: Item
    {
        #region -- PUBLIC --

        ///<summary>A shared trusted identity that acts as the root identity in the trust chain.</summary>
        public static Identity TrustedIdentity { get { lock(Identity._lock) { return Identity._trustedIdentity; } } }
        public const string TAG = "ID";
        public override string Tag { get { return Identity.TAG; } }
        public string SystemName { get { return this._claims.sys; } }
        public override Guid UniqueId { get { return this._claims.uid; } }
        /// <summary>A unique UUID (GUID) of the identity. Same as the "sub" field.</summary>
        public Guid SubjectId { get { return this._claims.sub; } }        
        /// <summary>The date when the identity was issued, i.e. approved by the issuer. Same as the "iat" field.</summary>
        public DateTime IssuedAt { get { return Utility.FromTimestamp(this._claims.iat); } }
        /// <summary>The date when the identity will expire and should not be accepted anymore. Same as the "exp" field.</summary>
        public DateTime ExpiresAt { get { return Utility.FromTimestamp(this._claims.exp); } } 
        /// <summary>A unique UUID (GUID) of the issuer of the identity. Same as the "iss" field. If same value as subjectId, then this is a self-issued identity.</summary>
        public Guid IssuerId { get { return this._claims.iss; } }
        /// <summary>The public key associated with the identity. Same as the "pub" claim.</summary>
        public string PublicKey { get { return this._claims.pub; } }
        /// <summary>The trust chain of signed public keys.</summary>
        public Identity TrustChain { get; internal set; }
        public IList<Capability> Capabilities { get { return (this._claims.cap != null) ? new List<string>(this._claims.cap).ConvertAll(str => { Capability cap; Enum.TryParse<Capability>(str, true, out cap); return cap; }) : null; } }
        public ReadOnlyDictionary<string, object> Principles { get { return (this._claims.pri != null) ? new ReadOnlyDictionary<string, object>(this._claims.pri) : null; } }
        public IList<string> Ambits { get { return (this._claims.amb != null) ? new List<string>(this._claims.amb).AsReadOnly() : null; } }
        public IList<string> Methods { get { return (this._claims.mtd != null) ? new List<string>(this._claims.mtd).AsReadOnly() : null; } }

        public bool IsSelfSigned { get { return (this.SubjectId == this.IssuerId && this.HasCapability(Capability.Self)); } }

        ///<summary>Set the shared trusted identity, which forms the basis of the trust chain. All identities will be verified
        /// from a trust perspecitve using this identity. For the trust chain to hold, then all identities must be either issued
        /// by this identity or other identities (with the 'issue' capability) that has been issued by this identity.
        ///<param name="trustedIdentity">The identity to set as the trusted identity.</param>
        public static void SetTrustedIdentity(Identity trustedIdentity)
        {
            lock(Identity._lock)
            {
                Identity._trustedIdentity = trustedIdentity;
            }
        }

        public Identity() { }

        public void VerifyTrust()
        {
            if (Identity.TrustedIdentity == null) { throw new InvalidOperationException("Unable to verify trust, no trusted identity set."); }
            DateTime now = DateTime.UtcNow;
            if (this.IssuedAt > now) { throw new DateExpirationException("Identity is not yet valid, issued at date in the future."); }
            if (this.IssuedAt > this.ExpiresAt) { throw new DateExpirationException("Invalid expiration date, expires at before issued at."); }
            if (this.ExpiresAt < now) { throw new DateExpirationException("Identity has expired."); }
            if (Identity._trustedIdentity.SystemName != this.SystemName) { throw new UntrustedIdentityException("Unable to trust identity, identity part of another system."); }
            if (this.TrustChain != null)
            {
                this.TrustChain.VerifyTrust();
            } 
            string publicKey = this.TrustChain != null ? this.TrustChain.PublicKey : Identity.TrustedIdentity.PublicKey;
            try {
                Crypto.VerifySignature(this._encoded, this._signature, Key.FromBase58Key(publicKey));
            } catch (IntegrityException) 
            {
                throw new UntrustedIdentityException("Identity cannot be trusted.");
            }
        }

        /// <summary>Will check if the identity has a specific capability.</summary>
        /// <param name="capability">The capability to check for.</param>
        /// <returns>Boolean to indicate if the identity has the capability or not.</returns>
        public bool HasCapability(Capability capability)
        {
            return this.Capabilities.Any(cap => cap == capability);
        }

        public bool HasAmbit(string ambit) {
            return this._claims.amb != null && this.Ambits.Any(cap => cap == ambit);
        }

        #endregion

        #region -- INTERNAL --

        internal new static Identity FromEncoded(string encoded)
        {
            Identity identity = new Identity();
            identity.Decode(encoded);
            return identity;
        }

        internal Identity(string systemName, Guid subjectId, string publicKey, DateTime issuedAt, DateTime expiresAt, Guid issuerId, List<Capability> capabilities, Dictionary<string, object> principles, List<string> ambits, List<string> methods) 
        {
            if (systemName == null || systemName.Length == 0) { throw new ArgumentNullException(nameof(systemName), "System name must not be null or empty."); }
            string[] cap = capabilities.ConvertAll(c => c.ToString().ToLower()).ToArray();
            string[] amb = (ambits != null && ambits.Count > 0) ? ambits.ConvertAll(c => c.ToString().ToLower()).ToArray() : null;
            string[] mtd = (methods != null && methods.Count > 0) ? methods.ConvertAll(c => c.ToString().ToLower()).ToArray() : null;
            this._claims = new IdentityClaims(systemName,
                                              Guid.NewGuid(), 
                                              subjectId, 
                                              issuerId, 
                                              Utility.ToTimestamp(issuedAt), 
                                              Utility.ToTimestamp(expiresAt), 
                                              publicKey, 
                                              cap, 
                                              principles, 
                                              amb,
                                              mtd);
        }

        protected override void Decode(string encoded) 
        {
            string[] components = encoded.Split(new char[] { Envelope._COMPONENT_DELIMITER });
            if (components.Length != Identity._NBR_EXPECTED_COMPONENTS_MIN &&
                components.Length != Identity._NBR_EXPECTED_COMPONENTS_MAX) { throw new FormatException($"Unexpected number of components for identity issuing request, expected {Identity._NBR_EXPECTED_COMPONENTS_MIN} or {Identity._NBR_EXPECTED_COMPONENTS_MAX}, got {components.Length}."); }
            if (components[Identity._TAG_INDEX] != Identity.TAG) { throw new FormatException($"Unexpected item tag, expected: \"{Identity.TAG}\", got \"{components[Identity._TAG_INDEX]}\"."); }
            byte[] json = Utility.FromBase64(components[Identity._CLAIMS_INDEX]);
            this._claims = JsonSerializer.Deserialize<IdentityClaims>(json);
            if (this._claims.sys == null || this._claims.sys.Length == 0) { throw new FormatException("System name missing from identity."); } 
            if (components.Length == Identity._NBR_EXPECTED_COMPONENTS_MAX) // There is also a trust chain identity 
            {
                byte[] issIdentity = Utility.FromBase64(components[Identity._CHAIN_INDEX]);
                this.TrustChain = Identity.FromEncoded(System.Text.Encoding.UTF8.GetString(issIdentity, 0, issIdentity.Length));
            }
            this._encoded = encoded.Substring(0, encoded.LastIndexOf(Envelope._COMPONENT_DELIMITER));
            this._signature = components[components.Length - 1];
        }

        protected override string Encode()
        {
            if (this._encoded == null)
            {
                StringBuilder builder = new StringBuilder();
                builder.Append(Identity.TAG);
                builder.Append(Envelope._COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(this._claims)));
                if (this.TrustChain != null)
                {
                    builder.Append(Envelope._COMPONENT_DELIMITER);
                    builder.Append(Utility.ToBase64($"{this.TrustChain.Encode()}{Envelope._COMPONENT_DELIMITER}{this.TrustChain._signature}"));
                }
                this._encoded = builder.ToString();
            }
            return this._encoded;
        }

        #endregion

        # region -- PROTECTED --

        #endregion

        #region -- PRIVATE --

        private const int _NBR_EXPECTED_COMPONENTS_MIN = 3;
        private const int _NBR_EXPECTED_COMPONENTS_MAX = 4;
        private const int _TAG_INDEX = 0;
        private const int _CLAIMS_INDEX = 1;
        private const int _CHAIN_INDEX = 2;
        private IdentityClaims _claims;
        private static readonly object _lock = new object();
        private static Identity _trustedIdentity;

        private struct IdentityClaims
        {
            public string sys { get; set; }
            public Guid uid { get; set; }
            public Guid sub { get; set; }
            public Guid iss { get; set; }
            public string iat { get; set; }
            public string exp { get; set; }
            public string pub { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] cap { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)][JsonConverter(typeof(DictionaryStringObjectJsonConverter))]
            public Dictionary<string, object> pri { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] amb { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string[] mtd { get; set; }

            [JsonConstructor]
            public IdentityClaims(string sys, Guid uid, Guid sub, Guid iss, string iat, string exp, string pub, string[] cap, Dictionary<string, object> pri, string[] amb, string[] mtd)
            {
                this.sys = sys;
                this.uid = uid;
                this.sub = sub;
                this.iss = iss;
                this.iat = iat;
                this.exp = exp;
                this.pub = pub;
                this.cap = cap;
                this.pri = pri;
                this.amb = amb;
                this.mtd = mtd;
            }

        }

        private static Object GetValueFromElement(System.Text.Json.JsonElement element) {
            switch (element.ValueKind) 
            {
                case JsonValueKind.Number: return element.GetDouble();
                case JsonValueKind.String: return element.GetString();
                case JsonValueKind.False: return false;
                case JsonValueKind.True: return true;
                case JsonValueKind.Null: return null;
                case JsonValueKind.Undefined: return null;
            }
            return element;
        }

        #endregion

    }

    class DictionaryStringObjectJsonConverter : JsonConverter<Dictionary<string, object>>
    {
        public override Dictionary<string, object> Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
        {
            if (reader.TokenType != JsonTokenType.StartObject)
            {
                throw new JsonException($"JsonTokenType was of type {reader.TokenType}, only objects are supported");
            }

            var dictionary = new Dictionary<string, object>();
            while (reader.Read())
            {
                if (reader.TokenType == JsonTokenType.EndObject)
                {
                    return dictionary;
                }

                if (reader.TokenType != JsonTokenType.PropertyName)
                {
                    throw new JsonException("JsonTokenType was not PropertyName");
                }

                var propertyName = reader.GetString();

                if (string.IsNullOrWhiteSpace(propertyName))
                {
                    throw new JsonException("Failed to get property name");
                }

                reader.Read();

                dictionary.Add(propertyName, ExtractValue(ref reader, options));
            }

            return dictionary;
        }

        public override void Write(Utf8JsonWriter writer, Dictionary<string, object> value, JsonSerializerOptions options)
        {
            JsonSerializer.Serialize(writer, value, options);
        }

        private object ExtractValue(ref Utf8JsonReader reader, JsonSerializerOptions options)
        {
            switch (reader.TokenType)
            {
                case JsonTokenType.String:
                    if (reader.TryGetDateTime(out var date))
                    {
                        return date;
                    }
                    return reader.GetString();
                case JsonTokenType.False:
                    return false;
                case JsonTokenType.True:
                    return true;
                case JsonTokenType.Null:
                    return null;
                case JsonTokenType.Number:
                    if (reader.TryGetInt64(out var result))
                    {
                        return result;
                    }
                    return reader.GetDecimal();
                case JsonTokenType.StartObject:
                    return Read(ref reader, null, options);
                case JsonTokenType.StartArray:
                    var list = new List<object>();
                    while (reader.Read() && reader.TokenType != JsonTokenType.EndArray)
                    {
                        list.Add(ExtractValue(ref reader, options));
                    }
                    return list.ToArray();
                default:
                    throw new JsonException($"'{reader.TokenType}' is not supported");
            }
        }
    }

}
