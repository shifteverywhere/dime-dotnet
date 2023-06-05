//
//  Envelope.cs
//  Dime - Data Integrity Message Envelope
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

namespace DiME;

/// <summary>
/// An encapsulating object that can carry one or more Dime items. This is usually the format that is exported and
/// stored or transmitted. It will start with the header 'Di'. Envelopes may be either anonymous or signed. An
/// anonymous envelope, most frequently used, is not cryptographically sealed, although the items inside normally
/// are. A signed envelope can contain one or more items and is itself also signed, it also has a small number of
/// claims attached to it.
/// </summary>
public class Envelope: Item
{

    /// <summary>
    /// The standard envelope header.
    /// </summary>
    public const string ItemHeader = "Di";
    /// <summary>
    /// Returns the tag of the Di:ME item.
    /// </summary>
    public override string Header => ItemHeader;
    /// <summary>
    /// Returns any attached Di:ME items. This will be an array of Item instances and may be cast by looking at the
    /// tag of the item (getTag).
    /// </summary>
    public IList<Item> Items => _items.AsReadOnly();
    /// <summary>
    /// Indicates if the envelope is anonymous (true) or if it is signed (false).
    /// </summary>
    public bool IsAnonymous => !HasClaims;

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
        claims?.Put(Claim.Iss, issuerId);
        claims?.Put(Claim.Iat, Utility.ToTimestamp(Utility.CreateDateTime()));
        if (context is not null)
            claims?.Put(Claim.Ctx, context);
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
        if (!encoded.StartsWith(ItemHeader)) { throw new FormatException("Not a Dime envelope object, invalid header."); }
        var sections = encoded.Split(Dime.SectionDelimiter);
        // 0: ENVELOPE
        var array = sections[0].Split(Dime.ComponentDelimiter);
        var envelope = new Envelope
        {
            Components = new List<string>(array)
        };
        // 1 to LAST or LAST - 1 
        //var endIndex = (envelope.IsAnonymous) ? sections.Length : sections.Length - 1; // end index dependent on anonymous envelope or not
        var items = new List<Item>(sections.Length);
        for (var index = 1; index < sections.Length; index++)
        {
            var item = Item.FromEncoded(sections[index]);
            if (item == null)
                if (index == sections.Length - 1) // This is most likely a signature
                    envelope.IsSigned = true;
                else
                    throw new FormatException("Unable to import envelope, encountered invalid items.");
            else
                items.Add(item);
        }
        envelope._items = items;
        if (!envelope.IsSigned)
            envelope.Encoded = encoded;
        else
        {
            envelope.Components.Add(sections[^1]);
            envelope.Encoded = encoded[..encoded.LastIndexOf(Dime.SectionDelimiter)];
            if (envelope.Signatures[0].IsLegacy)
                envelope.IsLegacy = true;
        }
        return envelope;
    }

    /// <summary>
    /// Adds a Dime item (of type Item or any subclass thereof) to the envelope. For signed envelopes, this needs to be
    /// done before signing the envelope. It is not possible to add an item twice to an envelope. It is also not
    /// possible to add another envelope to the envelope.
    /// to be done before signing the envelope.
    /// </summary>
    /// <param name="item">The Dime item to add.</param>
    /// <exception cref="InvalidOperationException">If envelope is already signed, or item already in envelope.</exception>
    public void AddItem(Item item)
    {
        if (IsSigned) { throw new InvalidOperationException("Unable to add item, envelope is already signed."); }
        if (item is Envelope) { throw new ArgumentException("Not allowed to add an envelope to another envelope.", nameof(item)); }
        var uid = item.GetClaim<Guid>(Claim.Uid);
        if (uid != null && GetItem<Guid>(Claim.Uid, uid) == null)
            _items.Add(item);
        else
            throw new InvalidOperationException($"Unable to add item, item with uid: {uid.ToString()}, is already added.");
    }

    /// <summary>
    /// Adds a list of Dime items (of type Item or any subclass thereof) to the envelope. For signed envelopes, this
    /// needs to be done before signing the envelope. It is not possible to add an item twice to an envelope. It is also
    /// not possible to add another envelope to the envelope.
    /// </summary>
    /// <param name="items">The Di:ME items to add.</param>
    /// <exception cref="InvalidOperationException"></exception>
    public void SetItems(IEnumerable<Item> items)
    {
        if (IsSigned) { throw new InvalidOperationException("Unable to set items, envelope is already signed."); }
        _items = new List<Item>();
        foreach (var item in items)
            AddItem(item);
    }
    
    /// <summary>
    /// Returns any item in the envelope that matches a specified claim and value. If no item could be found, then this
    /// will return null. Provided claim value must not be null.
    /// </summary>
    /// <param name="claim">The claim for which the provided value should be compared with.</param>
    /// <param name="value">The value of the claim that should be searched for.</param>
    /// <typeparam name="T">The expected type of the claim.</typeparam>
    /// <returns>The found item, or null if none could be found.</returns>
    public Item? GetItem<T>(Claim claim, T value)
    {
        return (from item in _items let compareValue = item.GetClaim<T>(claim) where compareValue != null && value.Equals(compareValue) select item).FirstOrDefault();
    }

    /// <summary>
    /// Returns any item inside the envelope that matches the provided context (ctx).
    /// </summary>
    /// <param name="context">The context to look for.</param>
    /// <returns>The found item, or null if none was found.</returns>
    [Obsolete("This is deprecated and will be removed in future versions, use GetItem<T>(Claim, T) instead.")]
    public Item? GetItem(string context)
    {
        return GetItem(Claim.Ctx, context);
    }
        
    /// <summary>
    /// Returns any item inside the envelope that matches the provided unique id (uid).
    /// </summary>
    /// <param name="uniqueId">The unique id to look for.</param>
    /// <returns>The found item, or null if none was found.</returns>
    [Obsolete("This is deprecated and will be removed in future versions, use GetItem<T>(Claim, T) instead.")]
    public Item? GetItem(Guid uniqueId)
    {
        return GetItem(Claim.Uid, uniqueId);
    }
    
    /// <summary>
    /// Returns any items in the envelope that matches a specified claim and value, If no items could be found, then this
    /// will return an empty array. Provided claim value must not be null.
    /// </summary>
    /// <param name="claim">The claim for which the provided value should be compared with.</param>
    /// <param name="value">The value of the claim that should be searched for.</param>
    /// <typeparam name="T">The expected type of the claim.</typeparam>
    /// <returns>All matching items, empty list if none were found.</returns>
    public List<Item> GetItems<T>(Claim claim, T value)
    {
        return (from item in _items let compareValue = item.GetClaim<T>(claim) where compareValue != null && value.Equals(compareValue) select item).ToList();
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
        if (IsLegacy)
        {
            if (IsAnonymous) { throw new InvalidOperationException("Unable to sign, envelope is anonymous."); }
            if (IsSigned) { throw new InvalidOperationException("Unable to sign, envelope is already signed."); }
        }
        if (_items == null || _items.Count == 0) { throw new InvalidOperationException("Unable to sign, at least one item must be attached before signing an envelope."); }
        base.Sign(key);
    }

    /// <summary>
    /// Exports the envelope to a Dime encoded string.
    /// </summary>
    /// <returns>The Dime encoded representation of the envelope.</returns>
    /// <exception cref="InvalidOperationException"></exception>
    public override string Export()
    {
        if (IsLegacy && !IsAnonymous && !IsSigned) { throw new InvalidOperationException("Unable to export, envelope is not signed."); }
        return Encode(IsSigned);
    }

    /// <inheritdoc />
    public override string GenerateThumbprint(string? suitName = null)
    {
        return Thumbprint(Encode(!IsAnonymous), suitName);
    }

    #region -- PROTECTED --

    /// <inheritdoc />
    protected override bool AllowedToSetClaimDirectly(Claim claim)
    {
        return AllowedClaims.Contains(claim);
    }
    
    /// <inheritdoc />
    protected override void CustomDecoding(List<string> components) { /* ignored */}

    /// <inheritdoc />
    protected override string Encode(bool withSignature)
    {
        if (Encoded is null)
        {
            var builder = new StringBuilder();
            builder.Append(ItemHeader);
            if (!IsAnonymous)
            {
                builder.Append(Dime.ComponentDelimiter);
                builder.Append((Utility.ToBase64(Claims()?.ToJson())));
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

    private static readonly List<Claim> AllowedClaims = new() { Claim.Amb, Claim.Aud, Claim.Ctx, Claim.Exp, Claim.Iat, Claim.Iss, Claim.Isu, Claim.Kid, Claim.Mtd, Claim.Sub, Claim.Sys, Claim.Uid };
    private List<Item> _items;
        
    #endregion

}