//
//  Tag.cs
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
using DiME.Exceptions;

namespace DiME;

/// <summary>
/// A Dime item that uses item links to cryptographically connect itself to other items. This may be done to create
/// different types of proof, for example after verification, reception or handling.
/// </summary>
public class Tag: Item
{
    #region -- PUBLIC --

    /// <summary>
    ///  The item header for DiME Tag items.
    /// </summary>
    public const string ItemHeader = "TAG";
    /// <summary>
    /// Returns the header of the DiME item.
    /// </summary>
    public override string Header => ItemHeader;

    /// <summary>
    /// Empty constructor, not to be used. Required for generics.
    /// </summary>
    public Tag() { }
    
    /// <summary>
    /// Will create a new Dime tag item.
    /// </summary>
    /// <param name="issuerId">The issuer of the item.</param>
    /// <param name="context"> The context of the item.</param>
    /// <param name="items">List of items that should be linked.</param>
    /// <exception cref="ArgumentException"></exception>
    public Tag(Guid issuerId, string? context = null, List<Item>? items = null)
    {
        if (context is {Length: > Dime.MaxContextLength}) 
            throw new ArgumentException($"Context must not be longer than {Dime.MaxContextLength}.", nameof(context));
        var claims = Claims();
        claims.Put(Claim.Uid, Guid.NewGuid());
        claims.Put(Claim.Iss, issuerId);
        claims.Put(Claim.Ctx, context);
        if (items is not null && items.Count > 0)
            SetItemLinks(items);
    }
    
    /// <summary>
    /// Verifies the signature of the tag item using a provided key and verifies a linked item from the proved item
    /// list. To verify correctly the linkedItem must be the original item that the data item was linked to.
    /// </summary>
    /// <param name="key">The key to used to verify the signature.</param>
    /// <param name="linkedItems">Items that are linked to the item being verified.</param>
    /// <exception cref="InvalidOperationException"></exception>
    /// <exception cref="FormatException"></exception>
    /// <exception cref="IntegrityException"></exception>
    public void Verify(Key key, List<Item>? linkedItems = null) { 
        // Verify IssuedAt and ExpiresAt
        var now = Utility.CreateDateTime();
        if (Utility.GracefulDateTimeCompare(IssuedAt, now) > 0)
            throw new DateExpirationException("Item is not yet valid, issued at date in the future.");
        if (Utility.GracefulDateTimeCompare(IssuedAt, ExpiresAt) > 0)
            throw new DateExpirationException("Invalid expiration date, expires at before issued at.");
        if (Utility.GracefulDateTimeCompare(ExpiresAt, now) < 0)
            throw new DateExpirationException("Item has expired.");
        base.Verify(key);
        if (linkedItems is not null)
            VerifyLinkedItems(linkedItems);
    }
    
    #endregion

    #region -- INTERNAL --

    internal override string ForExport()
    {
        if (ItemLinks is null || ItemLinks.Count == 0)
            throw new InvalidOperationException("Unable to export tag, must contain at least 1 linked item.");
        if (!IsSigned)
            throw new InvalidOperationException("Unable to export tag, must be signed first.");
        return base.ForExport();
    }

    #endregion
    
    #region -- PROTECTED --
    
    protected override void CustomDecoding(List<string> components)
    {
        IsSigned = true; // Tags are always signed
    }

    protected override int GetMinNbrOfComponents()
    {
        return MinimumNbrComponents;
    }

    #endregion

    #region -- PRIVATE --

    private new const int MinimumNbrComponents = 3;
    
    #endregion

}