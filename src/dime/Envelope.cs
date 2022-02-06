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

namespace ShiftEverywhere.DiME
{
    public class Envelope
    {
        public const int _MAX_CONTEXT_LENGTH = 84;
        public const string _HEADER = "Di";
        public const int _DIME_VERSION = 0x01;
        public Guid? IssuerId => _claims?.iss;
        public DateTime? IssuedAt => _claims.HasValue ? Utility.FromTimestamp(_claims.Value.iat) : null;
        public string Context => _claims?.ctx;
        public IList<Item> Items => _items?.AsReadOnly();
        public bool IsSigned => _signature != null;
        public bool IsAnonymous => !_claims.HasValue;

        public Envelope() { }

        public Envelope(Guid issuerId, string context = null)
        {
            var now = Utility.ToTimestamp(DateTime.UtcNow);
            if (context is {Length: > _MAX_CONTEXT_LENGTH}) { throw new ArgumentException($"Context must not be longer than {Envelope._MAX_CONTEXT_LENGTH}.", nameof(context)); }
            _claims = new DimeClaims(issuerId, now, context);
        }

        public static Envelope Import(string exported)
        {
            if (!exported.StartsWith(_HEADER)) { throw new FormatException("Not a Dime envelope object, invalid header."); }
            var sections = exported.Split(SectionDelimiter);
            // 0: HEADER
            var components = sections[0].Split(_COMPONENT_DELIMITER);
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
                dime._encoded = exported[..exported.LastIndexOf(SectionDelimiter)];
                dime._signature = sections.Last(); 
            }
            return dime;
        }

        public Envelope AddItem(Item item)
        {
            if (_signature != null) { throw new InvalidOperationException("Unable to add item, envelope is already signed."); }
            _items ??= new List<Item>();
            _items.Add(item);
            return this;
        }

        public Envelope SetItems(IEnumerable<Item> items)
        {
            if (_signature != null) { throw new InvalidOperationException("Unable to set items, envelope is already signed."); }
            _items = items.ToList();
            return this;
        }

        public Envelope Sign(Key key)
        {
            if (IsAnonymous) { throw new InvalidOperationException("Unable to sign, envelope is anonymous."); }
            if (_signature != null) { throw new InvalidOperationException("Unable to sign, envelope is already signed."); }
            if (_items == null || _items.Count == 0) { throw new InvalidOperationException("Unable to sign, at least one item must be attached before signing an envelope."); }
            _signature = Crypto.GenerateSignature(Encode(), key);
            return this;
        }

        public void Verify(string publicKey)
        {
            Verify(new Key(publicKey));
        }
        
        public Envelope Verify(Key key)
        {
            if (IsAnonymous) { throw new InvalidOperationException("Unable to verify, envelope is anonymous."); }
            if (_signature == null) { throw new InvalidOperationException("Unable to verify, envelope is not signed."); }
            Crypto.VerifySignature(Encode(), _signature, key);
            return this;
        }

        public string Export()
        {
            if (!IsAnonymous)
            {
                if (_signature == null) { throw new InvalidOperationException("Unable to export, envelope is not signed."); }
                return $"{Encode()}{SectionDelimiter}{_signature}";
            }
            else
                return Encode();
        }

        public string Thumbprint()
        {
            var encoded = IsAnonymous ? Encode() : $"{Encode()}{SectionDelimiter}{_signature}";
            return Envelope.Thumbprint(encoded);
        }

        public static string Thumbprint(string encoded)
        {
            return Utility.ToHex(Crypto.GenerateHash(encoded));
        }

        internal const char _COMPONENT_DELIMITER = '.';

        #region -- PRIVATE --

        private const char SectionDelimiter = ':';
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
                builder.Append(_COMPONENT_DELIMITER);
                builder.Append(Utility.ToBase64(JsonSerializer.Serialize(_claims)));
            }
            foreach(var item in _items)
            {
                builder.Append(SectionDelimiter);
                builder.Append(item.ToEncoded());
            }
            _encoded = builder.ToString();
            return _encoded;
        }

        #endregion

    }

}

