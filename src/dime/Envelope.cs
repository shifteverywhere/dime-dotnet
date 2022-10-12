//
//  Envelope.cs
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
#nullable enable
using System;
using System.Text;
using System.Collections.Generic;
using System.Linq;

namespace DiME
{
    /// <summary>
    /// An encapsulating object that can carry one or more Di:ME items. This is usually the format that is exported and
    /// stored or transmitted. It will start with the header 'Di'. Envelopes may be either anonymous or signed. An
    /// anonymous envelope, most frequently used, is not cryptographically sealed, although the items inside normally
    /// are. A signed envelope can contain one or more items and is itself also signed, it also has a small number of
    /// claims attached to it.
    /// </summary>
    public class Envelope: Item
    {
        /// <summary>
        /// The maximum length that the context claim may hold. This is also used for the context claim in messages.
        /// </summary>
        [Obsolete("Obsolete constant, use Dime.MaxContextLength instead.")]
        public const int _MAX_CONTEXT_LENGTH = Dime.MaxContextLength;
        /// <summary>
        /// The standard envelope header.
        /// </summary>
        public const string Header = "Di";
        /// <summary>
        /// The current version of the implemented Di:ME specification.
        /// </summary>
        ///  [Obsolete("Obsolete constant, use Dime.Version instead.")]
        public const int _DIME_VERSION = 0x01;
        /// <summary>
        /// Returns the tag of the Di:ME item.
        /// </summary>
        public override string Identifier => Header;
        /// <summary>
        /// Returns any attached Di:ME items. This will be an array of Item instances and may be cast by looking at the
        /// tag of the item (getTag).
        /// </summary>
        public IList<Item> Items => _items.AsReadOnly();
        /// <summary>
        /// Indicates if the envelope is anonymous (true) or if it is signed (false).
        /// </summary>
        public bool IsAnonymous => !HasClaims();

        /// <summary>
        /// Default constructor for an anonymous envelope.
        /// </summary>
        public Envelope()
        {
            _items = new List<Item>();
        }

        /// <summary>
        /// Constructor to create a signed envelope with the identifier of the issuer and a custom context claim. The
        /// context may be any valid text.
        /// </summary>
        /// <param name="issuerId">The identifier of the issuer, may not be null.</param>
        /// <param name="context">The context to attach to the envelope, may be null.</param>
        /// <exception cref="ArgumentException"></exception>
        public Envelope(Guid issuerId, string? context = null)
        {
            if (context is {Length: > Dime.MaxContextLength}) { throw new ArgumentException($"Context must not be longer than {Dime.MaxContextLength}.", nameof(context)); }
            _items = new List<Item>();
            var claims = Claims();
            claims.Put(Claim.Iss, issuerId);
            claims.Put(Claim.Iat, Utility.ToTimestamp(Utility.CreateDateTime()));
            if (context is not null)
                claims.Put(Claim.Ctx, context);
        }

        /// <summary>
        /// Imports an envelope from a Di:ME encoded string. This will not verify the envelope, this has to be done by
        /// calling verify separately.
        /// </summary>
        /// <param name="encoded">The encoded Di:ME envelope to import.</param>
        /// <returns>The imported Envelope instance.</returns>
        /// <exception cref="FormatException"></exception>
        public static Envelope Import(string encoded)
        {
            if (!encoded.StartsWith(Header)) { throw new FormatException("Not a Dime envelope object, invalid header."); }
            var sections = encoded.Split(Dime.SectionDelimiter);
            // 0: ENVELOPE
            var array = sections[0].Split(Dime.ComponentDelimiter);
            var envelope = new Envelope
            {
                Components = new List<string>(array)
            };
            // 1 to LAST or LAST - 1 
            var endIndex = (envelope.IsAnonymous) ? sections.Length : sections.Length - 1; // end index dependent on anonymous envelope or not
            var items = new List<Item>(endIndex - 1);
            for (var index = 1; index < endIndex; index++)
                items.Add(Item.FromEncoded(sections[index]) ?? throw new FormatException("Unable to import Dime item, unexpected format."));
            envelope._items = items;
            if (envelope.IsAnonymous)
                envelope.Encoded = encoded;
            else
            {
                envelope.IsSigned = true;
                envelope.Components.Add(sections[^1]);
                envelope.Encoded = encoded[..encoded.LastIndexOf(Dime.SectionDelimiter)];
                if (envelope.Signatures[0].IsLegacy)
                    envelope.IsLegacy = true;
            }
            return envelope;
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
            if (IsSigned) { throw new InvalidOperationException("Unable to add item, envelope is already signed."); }
            if (item is Envelope) { throw new ArgumentException("Not allowed to add an envelope to another envelope.", nameof(item)); }
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
            if (IsSigned) { throw new InvalidOperationException("Unable to set items, envelope is already signed."); }
            _items = items.ToList();
            return this;
        }

        /// <summary>
        /// Returns any item inside the envelope that matches the provided context (ctx).
        /// </summary>
        /// <param name="context">The context to look for.</param>
        /// <returns>The found item, or null if none was found.</returns>
        public Item? GetItem(string context)
        {
            if (context.Length == 0 || _items.Count == 0) return null;
            return (from item in _items let ctx = item.Context where ctx is not null && ctx.Equals(context) select item).FirstOrDefault();
        }
        
        /// <summary>
        /// Returns any item inside the envelope that matches the provided unique id (uid).
        /// </summary>
        /// <param name="uniqueId">The unique id to look for.</param>
        /// <returns>The found item, or null if none was found.</returns>
        public Item? GetItem(Guid uniqueId)
        {
            return _items.Count == 0 ? null : (from item in _items where item.UniqueId.Equals(uniqueId) select item).FirstOrDefault();
        }

        /// <summary>
        /// Signs the envelope using the provided key. The key must be of type IDENTITY. It is not possible to sign an
        /// anonymous envelope. It is also not possible to sign an envelope if it already has been signed or does not
        /// contain any Di:ME items.
        /// </summary>
        /// <param name="key">The key to use when signing.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public override void Sign(Key key)
        {
            if (IsAnonymous) { throw new InvalidOperationException("Unable to sign, envelope is anonymous."); }
            if (IsSigned) { throw new InvalidOperationException("Unable to sign, envelope is already signed."); }
            if (_items == null || _items.Count == 0) { throw new InvalidOperationException("Unable to sign, at least one item must be attached before signing an envelope."); }
            base.Sign(key);
        }
        
        /// <summary>
        /// Verifies the signature of the envelope using a provided key.
        /// </summary>
        /// <param name="key">The key to used to verify the signature, must not be null.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public override void Verify(Key key)
        {
            if (IsAnonymous) { throw new InvalidOperationException("Unable to verify, envelope is anonymous."); }
            base.Verify(key);
        }

        /// <summary>
        /// Exports the envelope to a Dime encoded string.
        /// </summary>
        /// <returns>The Dime encoded representation of the envelope.</returns>
        /// <exception cref="InvalidOperationException"></exception>
        public override string Export()
        {
            if (!IsAnonymous && !IsSigned) { throw new InvalidOperationException("Unable to export, envelope is not signed."); }
            return Encode(!IsAnonymous);
        }

        /// <summary>
        /// Returns the thumbprint of the envelope. This may be used to easily identify an envelope or detect if an
        /// envelope has been changed. This is created by securely hashing the envelope and will be unique and change as
        /// soon as any content changes.
        /// </summary>
        /// <returns>The hash of the envelope as a hex string.</returns>
        public override string Thumbprint()
        {
            return Thumbprint(Encode(!IsAnonymous));
        }

        #region -- PROTECTED --

        protected override void CustomDecoding(List<string> components) { /* ignored */}

        protected override string Encode(bool withSignature)
        {
            if (Encoded is null)
            {
                var builder = new StringBuilder();
                builder.Append(Envelope.Header);
                if (!IsAnonymous)
                {
                    builder.Append(Dime.ComponentDelimiter);
                    builder.Append((Utility.ToBase64(Claims().ToJson())));
                }
                foreach(var item in _items)
                {
                    builder.Append(Dime.SectionDelimiter);
                    builder.Append(item.ForExport());
                }
                Encoded = builder.ToString();
            }
            if (withSignature && IsSigned)
                return $"{Encoded}{Dime.SectionDelimiter}{Signature.ToEncoded(Signatures)}";
            return Encoded;
        }

        #endregion
        
        #region -- PRIVATE --

        private List<Item> _items;
        
        #endregion

    }

}

