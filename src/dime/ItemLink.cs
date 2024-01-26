//
//  ItemLink.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//

#nullable enable
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using DiME.KeyRing;

namespace DiME;

/// <summary>
/// Represents a link to a Dime item. This can be used to link Dime items together, which then would be signed and thus
/// create a cryptographic relationship.
/// </summary>
public sealed class ItemLink
{
    #region -- PUBLIC --

    /// <summary>
    /// The item identifier, this is used to determine the Dime item type, i.e. "ID", "MSG", etc.
    /// </summary>
    public string ItemIdentifier { get; private set; }
    /// <summary>
    /// The thumbprint of the linked item. Used to determine if an item is the linked item.
    /// </summary>
    public string Thumbprint { get; private set; }
    /// <summary>
    /// The unique ID of the linked item.
    /// </summary>
    public Guid UniqueId { get; private set; }
    /// <summary>
    /// The cryptographic suite used to generate the item link.
    /// </summary>
    public string? CryptoSuiteName { get; internal set; }

    /// <summary>
    /// Creates an item link from the provided Dime item.
    /// </summary>
    /// <param name="item">The Dime item to create the item link from.</param>
    /// <param name="cryptoSuiteName">The name of the cryptographic suite to use, may be null.</param>
    public ItemLink(Item item, string? cryptoSuiteName = null)
    {
        ItemIdentifier = item.Header;
        Thumbprint = item.GenerateThumbprint(false, cryptoSuiteName);
        UniqueId = item.GetClaim<Guid>(Claim.Uid);
        CryptoSuiteName = cryptoSuiteName ?? Dime.Crypto.DefaultSuiteName;
    }

    /// <summary>
    /// Creates an item link from the provided parameters.
    /// </summary>
    /// <param name="itemIdentifier">The Dime item identifier of the item, e.g. "ID", "MSG", etc.</param>
    /// <param name="thumbprint">The thumbprint of the item to which the link should be created.</param>
    /// <param name="uniqueId">The unique ID of the item to which the link should be created.</param>
    /// /// <param name="cryptoSuiteName">The name of the cryptographic suite used.</param>
    /// <exception cref="ArgumentException"></exception>
    public ItemLink(string itemIdentifier, string thumbprint, Guid uniqueId, string cryptoSuiteName)
    {
        if (string.IsNullOrEmpty(itemIdentifier))
            throw new ArgumentException("Provided item identifier must not be empty.", nameof(itemIdentifier));
        if (string.IsNullOrEmpty(thumbprint))
            throw new ArgumentException("Provided thumbprint must not be empty.", nameof(thumbprint));
        if (string.IsNullOrEmpty(cryptoSuiteName))
            throw new ArgumentException("Provided cryptographic suite must not be empty.", nameof(thumbprint));
        ItemIdentifier = itemIdentifier;
        Thumbprint = thumbprint;
        UniqueId = uniqueId;
        CryptoSuiteName = cryptoSuiteName;
    }

    /// <summary>
    /// Returns an ItemLink instance from an encoded string.
    /// </summary>
    /// <param name="encoded">The encoded string.</param>
    /// <returns>Decoded ItemLink instance.</returns>
    /// <exception cref="ArgumentException"></exception>
    /// <exception cref="FormatException"></exception>
    public static ItemLink FromEncoded(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            throw new ArgumentException("Encoded item link must not be null or empty.", nameof(encoded));
        var components = encoded.Split(new[] { Dime.ComponentDelimiter });
        if (components.Length < 3) throw new FormatException("Invalid item link format.");
        var suiteName = components.Length == 4 ? components[3] : "STN";
        return new ItemLink(components[0], components[2], Guid.Parse(components[1]), suiteName);
    }

    /// <summary>
    /// Returns a list of ItemLink instances from an encoded string.
    /// </summary>
    /// <param name="encodedList">The encoded string.</param>
    /// <returns>Decoded ItemLink instances in a list.</returns>
    /// <exception cref="ArgumentException"></exception>
    public static List<ItemLink> FromEncodedList(string encodedList)
    {
        if (string.IsNullOrEmpty(encodedList))
            throw new ArgumentException("Encoded list of item link must not be null or empty.", nameof(encodedList));
        var items = encodedList.Split(new[] {Dime.SectionDelimiter});
        return items.Select(FromEncoded).ToList();
    }

    /// <summary>
    /// Verifies if an item corresponds to the ItemLink.
    /// </summary>
    /// <param name="item">The item to verify against.</param>
    /// <returns>True if verified successfully.</returns>
    public bool Verify(Item item)
    {
        return UniqueId.Equals(item.GetClaim<Guid>(Claim.Uid)) 
               && ItemIdentifier.Equals(item.Header)
               && Thumbprint.Equals(item.GenerateThumbprint(false, CryptoSuiteName));
    }

    /// <summary>
    /// Verifies a list of items towards a list of ItemLink instances.
    /// </summary>
    /// <param name="items">The items to verify against.</param>
    /// <param name="links">The list of ItemLink instances.</param>
    public static IntegrityState Verify(List<Item> items, List<ItemLink> links)
    {
        if (items.Count == 0 || links.Count == 0) return IntegrityState.FailedLinkedItemMissing;
        foreach (var item in items)
        {
            var matchFound = false;
            foreach (var link in links.Where(link => link.UniqueId.Equals(item.GetClaim<Guid>(Claim.Uid))))
            {
                matchFound = true;
                if (!link.ItemIdentifier.Equals(item.Header) || !link.Thumbprint.Equals(item.GenerateThumbprint(false, link.CryptoSuiteName)))
                    return IntegrityState.FailedLinkedItemFault;
            }
            if (!matchFound)
                return IntegrityState.FailedLinkedItemMismatch;
        }
        return items.Count == links.Count ? IntegrityState.ValidItemLinks : IntegrityState.PartiallyValidItemLinks;
    }

    /// <summary>
    /// Encodes an ItemLink to a string for exporting.
    /// </summary>
    /// <returns>An encoded string.</returns>
    public string ToEncoded()
    {
        var builder = new StringBuilder();
        builder.Append(ItemIdentifier)
            .Append(Dime.ComponentDelimiter)
            .Append(UniqueId.ToString())
            .Append(Dime.ComponentDelimiter)
            .Append(Thumbprint);
        if (CryptoSuiteName != null && !CryptoSuiteName.Equals("STN"))
            builder.Append(Dime.ComponentDelimiter)
                .Append(CryptoSuiteName);
        return builder.ToString();
    }

    /// <summary>
    /// Encodes a list of ItemLink instances to a string for exporting.
    /// </summary>
    /// <param name="links">A list of ItemLink instances that should be encoded.</param>
    /// <returns>An encoded string.</returns>
    public static string? ToEncoded(List<ItemLink> links)
    {
        if (links.Count == 0) return null;
        var stringBuilder = new StringBuilder();
        foreach (var link in links)
        {
            if (stringBuilder.Length > 0)
                stringBuilder.Append(Dime.SectionDelimiter);
            stringBuilder.Append(link.ToEncoded());
        }
        return stringBuilder.ToString();
    }

    #endregion

}