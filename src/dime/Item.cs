//
//  Item.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using DiME.KeyRing;

#nullable enable
namespace DiME;

/// <summary>
/// Base class for any other type of DiME items that can be included inside an Envelope instance.
/// </summary>
public abstract class Item
{
    #region -- PUBLIC --

    /// <summary>
    /// Returns the header of the DiME item. This can be used to identify the type of DiME object held in
    /// this generic class. It is also used in the exported DiME format to indicate the beginning of a DiME item
    /// inside an envelope. Typically, this is represented by a short series of letters.
    /// </summary>
    public abstract string Header { get; }
    /// <summary>
    /// Checks if the item has been signed or not.
    /// </summary>
    public bool IsSigned { get; protected set; }
    /// <summary>
    /// Returns if the item is marked as legacy (compatible with Dime format before official version 1). 
    /// </summary>
    public virtual bool IsLegacy { get; internal set; }
        
    /// <summary>
    /// Will import an item from a Dime encoded string.Dime envelopes cannot be imported using this method, for
    /// envelopes use Envelope.importFromEncoded(String) instead.
    /// </summary>
    /// <param name="exported">The Dime encoded string to import an item from.</param>
    /// <typeparam name="T">The subclass of item of the imported Dime item.</typeparam>
    /// <returns>The imported Dime item.</returns>
    /// <exception cref="FormatException">If the encoded string is of a Dime envelope.</exception>
    public static T Import<T>(string exported) where T : Item, new()
    {
        var envelope = Envelope.Import(exported);
        if (envelope.Items is {Count: > 1})
        {
            throw new FormatException("Multiple items found, import as 'Envelope' instead.");
        }
        return (T) envelope.Items.First();
    }

    /// <summary>
    /// Exports the item to a Dime encoded string.
    /// </summary>
    /// <returns>The Dime encoded representation of the item.</returns>
    public virtual string Export()
    {
        var envelope = new Envelope();
        envelope.AddItem(this);
        return envelope.Export();
    }

    /// <summary>
    /// Returns the value of a claim that is associated with the item. The default value of the type for the claim is
    /// returned if there is no value to return (i.e. the item does not have that claim).
    /// </summary>
    /// <param name="claim">The claim to return the value for.</param>
    /// <typeparam name="T">The type of the expected return.</typeparam>
    /// <returns>The value of the claim, default value if none exists.</returns>
    public T? GetClaim<T>(Claim claim)
    {
        return HasClaims ? Claims()!.Get<T>(claim) : default;
    }

    /// <summary>
    /// Associates a value of a claim with the item.
    /// </summary>
    /// <param name="claim">The claim to add a value to.</param>
    /// <param name="value">The value of the claim</param>
    /// <exception cref="ArgumentException">If it is not allowed to set the claim on this item type.</exception>
    public void PutClaim(Claim claim, object value)
    {
        ThrowIfSigned();
        if (!AllowedToSetClaimDirectly(claim))
            throw new ArgumentException($"Unable to set claim '{claim}', may be unsupported or locked.", nameof(claim));
        SetClaimValue(claim, value);
    }

    /// <summary>
    /// Removes a claim and value associated with the item.
    /// </summary>
    /// <param name="claim">The claim to remove.</param>
    public void RemoveClaim(Claim claim)
    {
        ThrowIfSigned();
        Claims()?.Remove(claim);
    }

    /// <summary>
    /// Checks if the item has a value associated with a specified claim.
    /// </summary>
    /// <param name="claim">The claim to check for.</param>
    /// <returns>True if there is a value, false otherwise.</returns>
    public bool HasClaim(Claim claim)
    {
        return Claims()?.HasClaim(claim) ?? false;
    }
    
    /// <summary>
    /// Will sign an item with the proved key. The Key instance must contain a secret key and be of type IDENTITY.
    /// </summary>
    /// <param name="key">The key to sign the item with, must be of type IDENTITY.</param>
    /// <exception cref="InvalidOperationException"></exception>
    /// <exception cref="ArgumentNullException"></exception>
    public virtual void Sign(Key key)
    {
        if (IsLegacy && IsSigned)
            throw new InvalidOperationException("Unable to sign, legacy item is already signed.");
        if (key.Secret is null)
            throw new ArgumentNullException(nameof(key), "Unable to sign, key for signing must not be null.");
        if (IsSigned && Signature.Find(Dime.Crypto.GenerateKeyName(key), Signatures) is not null)
            throw new InvalidOperationException("Item already signed with provided key.");
        var signature = Dime.Crypto.GenerateSignature(Encode(false), key);
        var name = IsLegacy ? null : Dime.Crypto.GenerateKeyName(key);
        Signatures.Add(new Signature(signature, name));
        IsSigned = true;
    }

    /// <summary>
    ///  Will remove the signature of an item.
    /// </summary>
    /// <returns>True if the item was stripped of the signature, false otherwise.</returns>
    public bool Strip()
    {
        Encoded = null;
        Components = null;
        _signatures = null;
        IsSigned = false;
        return true;
    }
        
    /// <summary>
    /// Returns the thumbprint of the item. This may be used to easily identify an item or detect if an item has
    /// been changed. This is created by securely hashing the item and will be unique and change as soon as any
    /// content changes.
    /// </summary>
    /// <returns>The hash of the item as a hex string.</returns>
    public virtual string Thumbprint()
    {
        return Thumbprint(Encode(true));
    }

    /// <summary>
    /// Returns the thumbprint of a Di:ME encoded item string. This may be used to easily identify an item or detect
    /// if an item has been changed. This is created by securely hashing the item and will be unique and change as
    /// soon as any content changes. This will generate the same value as the instance method thumbprint for the
    /// same (and unchanged) item.
    /// </summary>
    /// <param name="encoded">The Di:ME encoded item string.</param>
    /// <returns>The hash of the item as a hex string.</returns>
    public static string Thumbprint(string encoded)
    {
        return Utility.ToHex(Dime.Crypto.GenerateHash(Encoding.UTF8.GetBytes(encoded)));
    }

    /// <summary>
    /// Verifies the integrity and over all validity and trust of the item. The verification will be made using the
    /// public key in the provided identity.
    /// </summary>
    /// <param name="verifyIdentity">The identity to use when verifying.</param>
    /// <param name="linkedItems">A list of item where item links should be verified, may be null.</param>
    /// <returns>The integrity state of the verification.</returns>
    public IntegrityState Verify(Identity verifyIdentity, List<Item>? linkedItems = null)
    {
        // TODO: check issue here
        return Verify(verifyIdentity.PublicKey, linkedItems);
    }
    
    /// <summary>
    /// Verifies the integrity and over all validity and trust of the item. If a key is provided, then verification will
    /// use that key. If verifyKey is omitted, then the local key ring will be used to verify signatures of the item.
    /// </summary>
    /// <param name="verifyKey">Key used to verify the item, may be null.</param>
    /// <param name="linkedItems">A list of item where item links should be verified, may be null.</param>
    /// <returns>The integrity state of the verification.</returns>
    public virtual IntegrityState Verify(Key? verifyKey = null, List<Item>? linkedItems = null)
    {
        var state = VerifySignature(verifyKey);
        if (!Dime.IsIntegrityStateValid(state)) 
            return state;
        if (linkedItems != null)
        {
            state = VerifyLinkedItems(linkedItems);
            if (!Dime.IsIntegrityStateValid(state)) 
                return state;
        }
        state = VerifyDates();
        return !Dime.IsIntegrityStateValid(state) ? state : IntegrityState.Complete;
    }

    /// <summary>
    /// Verifies any dates in the item. This will verify the validity period of the item, if it should be used or if it
    /// has expired. Failure here does not necessary mean that the item cannot be trusted, the dates of item is no
    /// longer valid, refer to the returned state.
    /// </summary>
    /// <returns>The integrity state of the verification.</returns>
    public IntegrityState VerifyDates()
    {
        if (!HasClaims) return IntegrityState.ValidDates;
        var now = Utility.CreateDateTime();
        if (Utility.GracefulDateTimeCompare(GetClaim<DateTime>(Claim.Iat), now) > 0)
            return IntegrityState.FailedUsedBeforeIssued;
        if (!HasClaim(Claim.Exp)) return IntegrityState.ValidDates;
        if (Utility.GracefulDateTimeCompare(GetClaim<DateTime>(Claim.Iat), GetClaim<DateTime>(Claim.Exp)) > 0)
            return IntegrityState.FailedDateMismatch;
        return Utility.GracefulDateTimeCompare(GetClaim<DateTime>(Claim.Exp), now) < 0 
            ? IntegrityState.FailedUsedAfterExpired : IntegrityState.ValidDates;
    }
    
    /// <summary>
    /// Verifies signatures of the item. The method will try to match an associated signature of the item to the
    /// provided key. If no key is provided, then the local key ring will be used to verify the item.
    /// </summary>
    /// <param name="verifyKey">The key to use for verification, may be null.</param>
    /// <returns>The integrity state of the verification.</returns>
    public IntegrityState VerifySignature(Key? verifyKey = null)
    {
        if (!IsSigned)
            return IntegrityState.FailedNoSignature;
        if (verifyKey is null)
            return Dime.KeyRing.Verify(this);
        var signature = IsLegacy ? Signatures[0] : Signature.Find(Dime.Crypto.GenerateKeyName(verifyKey), Signatures);
        if (signature is null)
            return IntegrityState.FailedKeyMismatch;
        try
        {
            return !Dime.Crypto.VerifySignature(Encode(false), signature.Bytes, verifyKey) 
                ? IntegrityState.FailedNotTrusted : IntegrityState.ValidSignature;
        }
        catch (Exception)
        {
            return IntegrityState.FailedInternalFault;
        }
    }

    /// <summary>
    /// Verifies any linked items to the item. This method will only verify that the list of provided items matches the
    /// links in the item. The signature of the item will not be verified.
    /// </summary>
    /// <param name="linkedItems">A list of item where item links should be verified.</param>
    /// <returns>The integrity state of the verification.</returns>
    public IntegrityState VerifyLinkedItems(List<Item> linkedItems)
    {
        ItemLinks ??= GetClaim<List<ItemLink>>(Claim.Lnk);
        return ItemLinks is not null ? ItemLink.Verify(linkedItems, ItemLinks) : IntegrityState.FailedLinkedItemMissing;
    }

    /// <summary>
    /// Will cryptographically link an item link from provided item to this item.
    /// </summary>
    /// <param name="item">The item to link to the tag.</param>
    public void AddItemLink(Item item)
    {
        ThrowIfSigned();
        ItemLinks ??= new List<ItemLink>();
        ItemLinks.Add(new ItemLink(item));
    }

    /// <summary>
    /// Will cryptographically link item links of provided items to this item.
    /// </summary>
    /// <param name="items">The items to link.</param>
    public void SetItemLinks(List<Item> items)
    {
        ThrowIfSigned();
        ItemLinks = new List<ItemLink>();
        foreach (var item in items)
            ItemLinks.Add(new ItemLink(item));
    }
        
    /// <summary>
    /// Returns a list of item links.
    /// </summary>
    /// <returns>A list of ItemLink instances, null if there are no links.</returns>
    public List<ItemLink>? GetItemLinks()
    {
        if (ItemLinks is not null) return ItemLinks;
        ItemLinks = Claims()?.Get<List<ItemLink>>(Claim.Lnk);
        return ItemLinks;
    }

    /// <summary>
    /// Removes all item links.
    /// </summary>
    public void RemoveLinkItems()
    {
        if (Claims()?.Get<string>(Claim.Lnk) is null) return;
        ThrowIfSigned();
        Claims()?.Remove(Claim.Lnk);
        ItemLinks = null;
    }
        
    /// <summary>
    /// Converts the item to legacy (compatible with earlier version of the Dime specification, before version 1)
    /// </summary>
    public virtual void ConvertToLegacy()
    { 
        Strip();
        IsLegacy = true;
    }

    #endregion

    #region -- INTERNAL --

    internal static Item? FromEncoded(string encoded)
    {
        var index = encoded.IndexOf(Dime.ComponentDelimiter);
        if (index == -1) return null;
        var t = TypeFromTag(encoded[..index]);
        if (t == null) return null;
        var item = (Item) Activator.CreateInstance(t)!;
        item.Decode(encoded);
        return item;
    }

    internal virtual string ForExport()
    {
        return Encode(true);
    }
        
    internal ClaimsMap? Claims()
    {
        if (_claims is not null) return _claims;
        if (Components is not null && Components.Count > ComponentsClaimsIndex)
        {
            var jsonClaims = Utility.FromBase64(Components[ComponentsClaimsIndex]);
            try
            {
                _claims = new ClaimsMap(Encoding.UTF8.GetString(jsonClaims));
            }
            catch (Exception)
            {
                return null;
            }
        }
        else
            _claims = new ClaimsMap();
        return _claims;
    }
        
    #endregion

    #region -- PROTECTED --

    /// <summary>The minimum number of components that must be present for a DiME item.</summary>
    protected const int MinimumNbrComponents = 2;
    /// <summary>
    /// The encoded DiME item. Needs to remain intact once created or imported, this so thumbprints and signature
    /// verifications will be correct. 
    /// </summary>
    protected string? Encoded;
    /// <summary>A list of raw and encoded components of the DiME item.</summary>
    protected List<string>? Components;
    /// <summary>A list of linked items.</summary>
    protected List<ItemLink>? ItemLinks;
    /// <summary>Indicates if an item has any claims attached to it.</summary>
    protected bool HasClaims => Claims()?.Size() > 0;
    /// <summary>
    /// For internal use. Will set a claim and value directly. No checks are applied if the item support the claim or not. 
    /// </summary>
    /// <param name="claim">The claim to set.</param>
    /// <param name="value">The value to set</param>
    protected void SetClaimValue(Claim claim, object? value)
    {
        Claims()?.Put(claim, value);
    }
    
    /// <summary>
    /// For internal use. Checks if the item supports a claim.
    /// </summary>
    /// <param name="claim">The claim to check.</param>
    /// <returns>True if allowed, false otherwise.</returns>
    protected abstract bool AllowedToSetClaimDirectly(Claim claim);
    
    /// <summary>
    /// Holds all signatures attached to the item.
    /// </summary>
    protected List<Signature> Signatures
    {
        get
        {
            if (_signatures is not null) return _signatures;
            _signatures = IsSigned ? Signature.FromEncoded(Components?[^1]) : new List<Signature>();
            return _signatures;
        }
    }
        
    /// <summary>
    /// Decodes an item. Abstract method that needs to be implemented in any subclass.
    /// </summary>
    /// <param name="encoded"></param>
    protected void Decode(string encoded)
    {
        var array = encoded.Split(new[] { Dime.ComponentDelimiter });
        if (array.Length < GetMinNbrOfComponents())
            throw new FormatException($"Unexpected number of components for Dime item, expected at least {GetMinNbrOfComponents()}, got {array.Length}.");
        if (!array[ComponentsIdentifierIndex].Equals(Header)) throw new FormatException($"Unexpected Dime item identifier, expected: {Header}, got {array[ComponentsClaimsIndex]}.");
        Components = new List<string>(array);
        CustomDecoding(Components);
        if (IsSigned)
        {
            IsLegacy = Signatures[0].IsLegacy;
            Encoded = encoded[..encoded.LastIndexOf(Dime.ComponentDelimiter)];
        }
        else
            Encoded = encoded;
    }

    /// <summary>
    /// Any additional decoding done by subclasses of Item.
    /// </summary>
    /// <param name="components">Components to decode.</param>
    protected abstract void CustomDecoding(List<string> components);

    /// <summary>
    /// Encodes an item and stores the result in Encoded. Abstract method that needs to be implemented in any
    /// subclass.
    /// </summary>
    /// <returns></returns>
    //protected abstract string Encode();

    protected virtual string Encode(bool withSignature)
    {
        if (Encoded is null)
        {
            var builder = new StringBuilder();
            CustomEncoding(builder);
            Encoded = builder.ToString();
        }
        if (withSignature && IsSigned)
        {
            return new StringBuilder()
                .Append(Encoded)
                .Append(Dime.ComponentDelimiter)
                .Append(Signature.ToEncoded(Signatures))
                .ToString();
        }
        return Encoded;
    }

    /// <summary>
    /// For internal use. Allows a subclass of item to do custom encoding when exporting an item.
    /// </summary>
    /// <param name="builder">The string builder for adding any encoded strings.</param>
    /// <exception cref="FormatException">If there is a problem with the encoding</exception>
    protected virtual void CustomEncoding(StringBuilder builder)
    {
        if (_claims is null) throw new FormatException("Unable to encode, item is missing claims.");
        builder.Append(Header);
        builder.Append(Dime.ComponentDelimiter);
        if (ItemLinks is not null && ItemLinks.Count > 0)
            Claims()?.Put(Claim.Lnk, ItemLink.ToEncoded(ItemLinks));
        builder.Append((Utility.ToBase64(_claims.ToJson())));    
    }

    /// <summary>
    /// Internal use. Allows subclasses of item to return the minimum number of components that make up the encoded
    /// DiME exported string for the item type.
    /// </summary>
    /// <returns>The minimum number of components.</returns>
    protected virtual int GetMinNbrOfComponents() {
        return MinimumNbrComponents;
    }
        
    /// <summary>
    /// Internal use. Checks if the Di:ME item is signed, and if it is, will throw an exception.
    /// </summary>
    /// <exception cref="InvalidOperationException">If the item is signed.</exception>
    protected void ThrowIfSigned() {
        if (IsSigned) { throw new InvalidOperationException("Unable to complete operation, Di:ME item already signed."); }
    }
        
    #endregion

    #region -- PRIVATE --

    /// <summary>The index number of the DiME item identifier string.</summary>
    private const int ComponentsIdentifierIndex = 0;
    /// <summary>The index number of the DiME item claims.</summary>
    private const int ComponentsClaimsIndex = 1;
    private ClaimsMap? _claims;
    private List<Signature>? _signatures;
        
    private static Type? TypeFromTag(string tag)
    {
        return tag switch
        {
            Identity.ItemHeader => typeof(Identity),
            IdentityIssuingRequest.ItemHeader => typeof(IdentityIssuingRequest),
            Message.ItemHeader => typeof(Message),
            Key.ItemHeader => typeof(Key),
            Tag.ItemHeader => typeof(Tag),
            Data.ItemHeader => typeof(Data),
            _ => null
        };
    }
        
    #endregion
        
}