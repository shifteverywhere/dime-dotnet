//
//  Envelope.cs
//  Di:ME - Digital Identity Message Envelope
//  Compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace DiME
{
    /// <summary>
    /// An encapsulating object that can carry one or more Di:ME items. This is usually the format that is exported and
    /// stored or transmitted. It will start with the header 'Di'. Envelopes may be either anonymous or signed. An
    /// anonymous envelope, most frequently used, is not cryptographically sealed, although the items inside normally
    /// are. A signed envelope can contain one or more items and is itself also signed, it also has a small number of
    /// claims attached to it.
    /// </summary>
    public class Envelope
    {
        /// <summary>
        /// The maximum length that the context claim may hold. This is also used for the context claim in messages.
        /// </summary>
        public const int _MAX_CONTEXT_LENGTH = 84;
        /// <summary>
        /// The standard envelope header.
        /// </summary>
        public const string _HEADER = "Di";
        /// <summary>
        /// The current version of the implemented Di:ME specification.
        /// </summary>
        public const int _DIME_VERSION = 0x01;
        /// <summary>
        /// Returns the identifier of the issuer of the envelope. Only applicable for signed envelopes.
        /// </summary>
        public Guid? IssuerId => _claims?.iss;
        /// <summary>
        /// Returns the date in UTC when this envelope was issued. Only applicable for signed envelopes.
        /// </summary>
        public DateTime? IssuedAt => _claims.HasValue ? Utility.FromTimestamp(_claims.Value.iat) : null;
        /// <summary>
        /// Returns the context that is attached to the envelope. Only applicable for signed envelopes.
        /// </summary>
        public string Context => _claims?.ctx;
        /// <summary>
        /// Returns any attached Di:ME items. This will be an array of Item instances and may be cast by looking at the
        /// tag of the item (getTag).
        /// </summary>
        public IList<Item> Items => _items?.AsReadOnly();
        /// <summary>
        /// Indicates if the envelope has a signature attached to it. This does not indicate if the envelope is signed
        /// or anonymous, as a tobe signed envelope will return false here before it is signed.
        /// </summary>
        public bool IsSigned => _signature != null;
        /// <summary>
        /// Indicates if the envelope is anonymous (true) or if it is signed (false).
        /// </summary>
        public bool IsAnonymous => !_claims.HasValue;

        /// <summary>
        /// Default constructor for an anonymous envelope.
        /// </summary>
        public Envelope() { }

        /// <summary>
        /// Constructor to create a signed envelope with the identifier of the issuer and a custom context claim. The
        /// context may be any valid text.
        /// </summary>
        /// <param name="issuerId">The identifier of the issuer, may not be null.</param>
        /// <param name="context">The context to attach to the envelope, may be null.</param>
        /// <exception cref="ArgumentException"></exception>
        public Envelope(Guid issuerId, string context = null)
        {
            var now = Utility.ToTimestamp(DateTime.UtcNow);
            if (context is {Length: > _MAX_CONTEXT_LENGTH}) { throw new ArgumentException($"Context must not be longer than {_MAX_CONTEXT_LENGTH}.", nameof(context)); }
            _claims = new DimeClaims(issuerId, now, context);
        }

        /// <summary>
        /// Imports an envelope from a Di:ME encoded string. This will not verify the envelope, this has to be done by
        /// calling verify separately.
        /// </summary>
        /// <param name="exported">The encoded Di:ME envelope to import.</param>
        /// <returns>The imported Envelope instance.</returns>
        /// <exception cref="FormatException"></exception>
        public static Envelope Import(string exported)
        {
            if (!exported.StartsWith(_HEADER)) { throw new FormatException("Not a Dime envelope object, invalid header."); }
            var sections = exported.Split(Dime.SectionDelimiter);
            // 0: HEADER
            var components = sections[0].Split(Dime.ComponentDelimiter);
            Envelope dime;
            switch (components.Length)
            {
                case 1:
                    dime = new Envelope();
                    break;
                case 2:
                    var claims = JsonSerializer.Deserialize<DimeClaims>(Utility.FromBase64(components[1]));
                    dime = new Envelope(claims);
                    break;
                default:
                    throw new FormatException($"Not a valid Di:ME envelope object, unexpected number of components in header, got: '{components.Length}', expected: '1' or '2'");
            }
            // 1 to LAST or LAST - 1 
            var endIndex = (dime.IsAnonymous) ? sections.Length : sections.Length - 1; // end index dependent on anonymous Di:ME or not
            var items = new List<Item>(endIndex - 1);
            for (var index = 1; index < endIndex; index++)
                items.Add(Item.FromEncoded(sections[index]));
            dime._items = items;
            if (dime.IsAnonymous)
               dime._encoded = exported;
            else
            {
                dime._encoded = exported[..exported.LastIndexOf(Dime.SectionDelimiter)];
                dime._signature = sections.Last(); 
            }
            return dime;
        }

        /// <summary>
        /// Adds a Di:ME item (of type Item or any subclass thereof) to the envelope. For signed envelopes, this needs
        /// to be done before signing the envelope.
        /// </summary>
        /// <param name="item">The Di:ME item to add.</param>
        /// <returns>Returns the Envelope instance for convenience.</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public Envelope AddItem(Item item)
        {
            if (_signature != null) { throw new InvalidOperationException("Unable to add item, envelope is already signed."); }
            _items ??= new List<Item>();
            _items.Add(item);
            return this;
        }

        /// <summary>
        /// Adds a list of Di:ME items (of type Item or any subclass thereof) to the envelope. For signed envelopes,
        /// this needs to be done before signing the envelope.
        /// </summary>
        /// <param name="items">The Di:ME items to add.</param>
        /// <returns>Returns the Envelope instance for convenience.</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public Envelope SetItems(IEnumerable<Item> items)
        {
            if (_signature != null) { throw new InvalidOperationException("Unable to set items, envelope is already signed."); }
            _items = items.ToList();
            return this;
        }

        /// <summary>
        /// Signs the envelope using the provided key. The key must be of type IDENTITY. It is not possible to sign an
        /// anonymous envelope. It is also not possible to sign an envelope if it already has been signed or does not
        /// contain any Di:ME items.
        /// </summary>
        /// <param name="key">The key to use when signing.</param>
        /// <returns>Returns the Envelope instance for convenience.</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public Envelope Sign(Key key)
        {
            if (IsAnonymous) { throw new InvalidOperationException("Unable to sign, envelope is anonymous."); }
            if (_signature != null) { throw new InvalidOperationException("Unable to sign, envelope is already signed."); }
            if (_items == null || _items.Count == 0) { throw new InvalidOperationException("Unable to sign, at least one item must be attached before signing an envelope."); }
            _signature = Crypto.GenerateSignature(Encode(), key);
            return this;
        }

        /// <summary>
        /// Verifies the signature of the envelope using a provided key.
        /// </summary>
        /// <param name="publicKey">The key to used to verify the signature, must not be null.</param>
        public void Verify(string publicKey)
        {
            Verify(new Key(publicKey));
        }
        
        /// <summary>
        /// Verifies the signature of the envelope using a provided key.
        /// </summary>
        /// <param name="key">The key to used to verify the signature, must not be null.</param>
        /// <returns>Returns the Envelope instance for convenience.</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public Envelope Verify(Key key)
        {
            if (IsAnonymous) { throw new InvalidOperationException("Unable to verify, envelope is anonymous."); }
            if (_signature == null) { throw new InvalidOperationException("Unable to verify, envelope is not signed."); }
            Crypto.VerifySignature(Encode(), _signature, key);
            return this;
        }

        /// <summary>
        /// Exports the envelope to a Di:ME encoded string.
        /// </summary>
        /// <returns>The Di:ME encoded representation of the envelope.</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public string Export()
        {
            if (IsAnonymous) return Encode();
            if (_signature == null) { throw new InvalidOperationException("Unable to export, envelope is not signed."); }
            return $"{Encode()}{Dime.SectionDelimiter}{_signature}";
        }

        /// <summary>
        /// Returns the thumbprint of the envelope. This may be used to easily identify an envelope or detect if an
        /// envelope has been changed. This is created by securely hashing the envelope and will be unique and change as
        /// soon as any content changes.
        /// </summary>
        /// <returns>The hash of the envelope as a hex string.</returns>
        public string Thumbprint()
        {
            var encoded = IsAnonymous ? Encode() : $"{Encode()}{Dime.SectionDelimiter}{_signature}";
            return Thumbprint(encoded);
        }

        /// <summary>
        /// Returns the thumbprint of a Di:ME encoded envelope string. This may be used to easily identify an envelope
        /// or detect if an envelope has been changed. This is created by securely hashing the envelope and will be
        /// unique and change as soon as any content changes. This will generate the same value as the instance method
        /// thumbprint or the same (and unchanged) envelope.
        /// </summary>
        /// <param name="encoded">The Di:ME encoded envelope string.</param>
        /// <returns>The hash of the envelope as a hex string.</returns>
        public static string Thumbprint(string encoded)
        {
            return Utility.ToHex(Crypto.GenerateHash(encoded));
        }
        
        #region -- PRIVATE --

        private List<Item> _items;
        private string _encoded;
        private string _signature;
        private readonly DimeClaims? _claims;

        private struct DimeClaims
        {
            public Guid iss { get; set; }
            public string iat { get; set; }
            [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
            public string ctx { get; set; }

            [JsonConstructor]
            public DimeClaims(Guid iss, string iat, string ctx)
            {
                this.iss = iss;
                this.iat = iat;
                this.ctx = ctx;
            }

        }

        private Envelope(DimeClaims claims)
        {
            _claims = claims;
        }

        private string Encode()
        {
            if (_encoded != null) return _encoded;
            var builder = new StringBuilder();
            builder.Append(_HEADER);
            if (!IsAnonymous)
            {
                builder.Append(Dime.ComponentDelimiter);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(_claims)));
            }
            foreach(var item in _items)
            {
                builder.Append(Dime.SectionDelimiter);
                builder.Append(item.ForExport());
            }
            _encoded = builder.ToString();
            return _encoded;
        }

        #endregion

    }

}

