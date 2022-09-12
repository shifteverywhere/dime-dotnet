//
//  Identity.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Linq;
using System.Collections.Generic;
using System.Collections.ObjectModel;

namespace DiME
{
    ///<summary>
    /// Represents a digital identity of an entity. Can be self-signed or signed by a trusted identity (and thus be part
    /// of a trust chain.
    ///</summary>
    public class Identity: Item
    {
        #region -- PUBLIC --

        /// <summary>
        /// A shared trusted identity that acts as the root identity in the trust chain.
        /// </summary>
        [Obsolete("Obsolete method, use Dime.TrustedIdentity instead.")]        
        public static Identity TrustedIdentity => Dime.TrustedIdentity;
        /// <summary>
        /// A tag identifying the Di:ME item type, part of the header.
        /// </summary>
        public const string _TAG = "ID";
        /// <summary>
        /// Returns the tag of the Di:ME item.
        /// </summary>
        public override string Tag => _TAG;
        /// <summary>
        /// Returns the name of the system or network that the entity belongs to. If issued by another entity and part
        /// of a trust chain, then all entities will share the same system name.
        /// </summary>
        public string SystemName => _claims.sys;
        /// <summary>
        /// Returns a unique identifier for the instance. This will be assigned when issuing an identity, but will
        /// change with each re-issuing even if it is for the same entity.
        /// </summary>
        public override Guid UniqueId => _claims.uid;
        /// <summary>
        /// Returns the entity's subject identifier. This is, within the system, defined by system name, unique for one
        /// specific entity.
        /// </summary>
        public Guid SubjectId => _claims.sub;
        /// <summary>
        /// The date and time when this identity was issued. Although, this date will most often be in the past, the
        /// identity should not be used and not trusted before this date.
        /// </summary>
        public DateTime IssuedAt => Utility.FromTimestamp(_claims.iat);
        /// <summary>
        /// The date and time when the identity will expire, and should not be used and not trusted anymore.
        /// </summary>
        public DateTime ExpiresAt => Utility.FromTimestamp(_claims.exp);
        /// <summary>
        /// Returns the issuer's subject identifier. The issuer is the entity that has issued the identity to another
        /// entity. If this value is equal to the subject identifier, then this identity is self-issued.
        /// </summary>
        public Guid IssuerId => _claims.iss;
        /// <summary>
        /// Returns the public key attached to the identity of an entity. The Key instance returned will only contain a
        /// public key or type IDENTITY.
        /// </summary>
        public Key PublicKey => _claims.pub is {Length: > 0} ? Key.FromBase58Key(_claims.pub) : null;
        /// <summary>
        /// Returns the parent identity of a trust chain for an identity. This is the issuing identity.
        /// </summary>
        public Identity TrustChain { get; internal set; }
        /// <summary>
        /// Returns a list of any capabilities given to an identity. These are requested by an entity and approved (and
        /// potentially modified) by the issuing entity when issuing a new identity. Capabilities are usually used to
        /// determine what an entity may do with its issued identity.
        /// </summary>
        public IEnumerable<Capability> Capabilities { get { return _claims.cap != null ? new List<string>(_claims.cap).ConvertAll(str => {
            Enum.TryParse(str, true, out Capability cap); return cap; }) : null; } }
        /// <summary>
        /// Returns all principles assigned to an identity. These are key-value fields that further provide information
        /// about the entity. Using principles are optional.
        /// </summary>
        public ReadOnlyDictionary<string, object> Principles => _claims.pri != null ? new ReadOnlyDictionary<string, object>(_claims.pri) : null;
        /// <summary>
        /// Returns an ambit list assigned to an identity. An ambit defines the scope, region or role where an identity
        /// may be used.
        /// </summary>
        public IList<string> Ambits => _claims.amb != null ? new List<string>(_claims.amb).AsReadOnly() : null;
        /// <summary>
        /// Returns a list of methods associated with an identity. The usage of this is normally context or application
        /// specific, and may specify different methods that can be used convert, transfer or further process a Di:ME
        /// identity.
        /// </summary>
        public IList<string> Methods => _claims.mtd != null ? new List<string>(_claims.mtd).AsReadOnly() : null;
        /// <summary>
        /// Returns if the identity has been self-issued. Self-issuing happens when the same entity issues its own identity.
        /// </summary>
        public bool IsSelfSigned => SubjectId == IssuerId && HasCapability(Capability.Self);

        /// <summary>
        /// Sets an Identity instance to be the trusted identity used for verifying a trust chain of other Identity
        /// instances. This is normally the root identity of a trust chain.
        /// </summary>
        /// <param name="trustedIdentity">The identity to set as the trusted identity.</param>
        [Obsolete("Obsolete method, use Dime.TrustedIdentity instead.")] 
        public static void SetTrustedIdentity(Identity trustedIdentity) { Dime.TrustedIdentity = trustedIdentity; }

        public Identity() { }

        /// <summary>
        /// Verifies if an Identity instance is valid and can be trusted. Will validate issued at and expires at dates, look at a trust chain (if present) and verify the signature with the attached public key.
        /// </summary>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="DateExpirationException">If the issued at date is in the future, or if the expires at date is in the past.</exception>
        /// <exception cref="UntrustedIdentityException">If the trust of the identity could not be verified.</exception>
        [Obsolete("This method is deprecated since 1.0.1 and will be removed in a future version use IsTrusted() or IsTrusted(Identity) instead.")]
        public void VerifyTrust()
        {
            if (!IsTrusted()) 
            {
                throw new UntrustedIdentityException("Identity cannot be trusted.");
            }
        }

        /// <summary>
        /// Will verify if an identity can be trusted using the globally set Trusted Identity
        /// (SetTrustedIdentity(Identity)). Once trust has been established it will also verify the issued at date and
        /// the expires at date to see if these are valid.
        /// </summary>
        /// <returns>True if the identity is trusted.</returns>
        /// <exception cref="InvalidOperationException">If global trusted identity is not set.</exception>
        public bool IsTrusted()
        {
            if (TrustedIdentity == null) { throw new InvalidOperationException("Unable to verify trust, no global trusted identity set."); }
            return IsTrusted(TrustedIdentity);
        }

        /// <summary>
        /// Will verify if an identity can be trusted by a provided identity. An identity is trusted if it exists on the
        /// same branch and later in the branch as the provided identity. Once trust has been established it will also
        /// verify the issued at date and the expires at date to see if these are valid.
        /// </summary>
        /// <param name="trustedIdentity">The identity to verify the trust from.</param>
        /// <returns>True if the identity is trusted.</returns>
        /// <exception cref="DateExpirationException">If the issued at date is in the future, or if the expires at date is in the past.</exception>
        public bool IsTrusted(Identity trustedIdentity)
        {
            if (trustedIdentity == null) { throw new ArgumentNullException(nameof(trustedIdentity),"Unable to verify trust, provided trusted identity must not be null."); }
            if (VerifyChain(trustedIdentity) == null) return false;
            var now = DateTime.UtcNow;
            if (IssuedAt > now) { throw new DateExpirationException("Identity is not yet valid, issued at date in the future."); }
            if (IssuedAt > ExpiresAt) { throw new DateExpirationException("Invalid expiration date, expires at before issued at."); }
            if (ExpiresAt < now) { throw new DateExpirationException("Identity has expired."); }
            return true;
        }
        
        

        /// <summary>
        /// Will check if the identity has a specific capability.
        /// </summary>
        /// <param name="capability">The capability to check for.</param>
        /// <returns>Boolean to indicate if the identity has the capability or not.</returns>
        public bool HasCapability(Capability capability)
        {
            return Capabilities.Any(cap => cap == capability);
        }

        /// <summary>
        /// Will check if an identity is within a particular ambit.
        /// </summary>
        /// <param name="ambit">The ambit to check for.</param>
        /// <returns>true or false</returns>
        public bool HasAmbit(string ambit) {
            return _claims.amb != null && Ambits.Any(cap => cap == ambit);
        }

        #endregion

        #region -- INTERNAL --

        internal Identity(string systemName, Guid subjectId, string publicKey, DateTime issuedAt, DateTime expiresAt, Guid issuerId, List<Capability> capabilities, Dictionary<string, object> principles, List<string> ambits, List<string> methods) 
        {
            if (string.IsNullOrEmpty(systemName)) { throw new ArgumentNullException(nameof(systemName), "System name must not be null or empty."); }
            var cap = capabilities.ConvertAll(c => c.ToString().ToLower()).ToArray();
            var amb = ambits is {Count: > 0} ? ambits.ConvertAll(c => c.ToString().ToLower()).ToArray() : null;
            var mtd = methods is {Count: > 0} ? methods.ConvertAll(c => c.ToString().ToLower()).ToArray() : null;
            _claims = new IdentityClaims(systemName, 
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
            var components = encoded.Split(new[] { Dime.ComponentDelimiter });
            if (components.Length != NbrExpectedComponentsMin &&
                components.Length != NbrExpectedComponentsMax) { throw new FormatException($"Unexpected number of components for identity issuing request, expected {NbrExpectedComponentsMin} or {NbrExpectedComponentsMax}, got {components.Length}."); }
            if (components[TagIndex] != _TAG) { throw new FormatException($"Unexpected item tag, expected: \"{_TAG}\", got \"{components[TagIndex]}\"."); }
            var json = Utility.FromBase64(components[ClaimsIndex]);
            _claims = JsonSerializer.Deserialize<IdentityClaims>(json);
            if (string.IsNullOrEmpty(_claims.sys)) { throw new FormatException("System name missing from identity."); } 
            if (components.Length == NbrExpectedComponentsMax) // There is also a trust chain identity 
            {
                var issIdentity = Utility.FromBase64(components[ChainIndex]);
                TrustChain = FromEncoded(Encoding.UTF8.GetString(issIdentity, 0, issIdentity.Length));
            }
            Encoded = encoded[..encoded.LastIndexOf(Dime.ComponentDelimiter)];
            Signature = components[^1];
        }

        protected override string Encode()
        {
            if (Encoded != null) return Encoded;
            var builder = new StringBuilder();
            builder.Append(_TAG);
            builder.Append(Dime.ComponentDelimiter);
            builder.Append(Utility.ToBase64(JsonSerializer.Serialize(_claims)));
            if (TrustChain != null)
            {
                builder.Append(Dime.ComponentDelimiter);
                builder.Append(Utility.ToBase64($"{TrustChain.Encode()}{Dime.ComponentDelimiter}{TrustChain.Signature}"));
            }
            Encoded = builder.ToString();
            return Encoded;
        }

        #endregion

        # region -- PROTECTED --

        #endregion

        #region -- PRIVATE --

        private const int NbrExpectedComponentsMin = 3;
        private const int NbrExpectedComponentsMax = 4;
        private const int TagIndex = 0;
        private const int ClaimsIndex = 1;
        private const int ChainIndex = 2;
        private IdentityClaims _claims;
        private static readonly object Lock = new();
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

        private new static Identity FromEncoded(string encoded)
        {
            var identity = new Identity();
            identity.Decode(encoded);
            return identity;
        }

        private Identity VerifyChain(Identity trustedIdentity)
        {
            Identity verifyingIdentity;
            if (TrustChain != null && TrustChain.SubjectId.CompareTo(trustedIdentity.SubjectId) != 0)
            {
                verifyingIdentity = TrustChain.VerifyChain(trustedIdentity);
            }
            else
            {
                verifyingIdentity = trustedIdentity;
            }
            if (verifyingIdentity == null) return null;
            try
            {
                Verify(verifyingIdentity.PublicKey);
                return this;
            }
            catch (IntegrityException)
            {
                return null;
            }
        }
        
        #endregion

    }

    internal class DictionaryStringObjectJsonConverter : JsonConverter<Dictionary<string, object>>
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
                case JsonTokenType.None:
                case JsonTokenType.EndObject:
                case JsonTokenType.EndArray:
                case JsonTokenType.PropertyName:
                case JsonTokenType.Comment:
                default:
                    throw new JsonException($"'{reader.TokenType}' is not supported");
            }
        }
    }

}
