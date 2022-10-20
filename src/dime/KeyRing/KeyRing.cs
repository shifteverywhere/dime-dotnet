//
//  KeyRing.cs
//  Dime - Data Integrity Message Envelope
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

namespace DiME.KeyRing;

/// <summary>
/// DiME uses a key ring to verify trust. This is done by storing trusted keys and identities in the key ring and then
/// calling Item.verify() to verify the trust against those keys and identities.
/// </summary>
public class KeyRing
{

    #region -- PUBLIC --
    
    /// <summary>
    /// Returns the number of name-item mappings in this key ring.
    /// </summary>
    public int Size => _keyRing?.Count ?? 0;

    /// <summary>
    /// Indicates if the key ring is empty or not.
    /// </summary>
    public bool IsEmpty => (_keyRing?.Count ?? 0) == 0;

    /// <summary>
    /// Checks if an item is part of the key ring.
    /// </summary>
    /// <param name="item">The item to check for.</param>
    /// <returns>True if item is part of the key ring, false otherwise.</returns>
    public bool Contains(Item item)
    {
        if (_keyRing is null) return false;
        switch (item)
        {
            case Key key:
            {
                var name = Dime.Crypto.GenerateKeyIdentifier(key);
                if (_keyRing.ContainsKey(name))
                {
                    var ringKey = (Key) _keyRing[name];
                    return ringKey.Public.Equals(key.Public);
                }
                break;
            }
            case Identity identity:
            {
                var name = identity.SubjectId.ToString().ToLower();
                if (_keyRing.ContainsKey(name))
                {
                    var ringIdentity = (Identity) _keyRing[name];
                    return ringIdentity.SubjectId.Equals(identity.SubjectId) &&
                           ringIdentity.PublicKey.Public.Equals(identity.PublicKey.Public);
                }
                break;
            }
        }
        return false;
    }

    /// <summary>
    /// Returns an item from the key ring.
    /// </summary>
    /// <param name="name">The name of the item to return.</param>
    /// <returns>The found item, null if none were found.</returns>
    public Item? Get(string name) => _keyRing?[name];

    /// <summary>
    /// Adds a Key or Identity instance to the key ring.
    /// </summary>
    /// <param name="item">The item to add.</param>
    /// <returns>The name associated with the item added.</returns>
    /// <exception cref="ArgumentException">If a invalid item is provided.</exception>
    public string Put(Item item)
    {
        var name = KeyRing.ItemName(item);
        if (string.IsNullOrEmpty(name)) throw new ArgumentException("Unable to add item to key ring, invalid item.", nameof(item));
        _keyRing ??= new Dictionary<string, Item>();
        _keyRing[name] = item;
        return name;
    }
    
    /// <summary>
    /// Removes a Key or Identity instance from the key ring. 
    /// </summary>
    /// <param name="item">The item to remove.</param>
    /// <returns>True if item was removed, false is it could not be found.</returns>
    public bool Remove(Item item)
    {
        var name = ItemName(item);
        return name is not null && Remove(name);
    }

    /// <summary>
    /// Removes an item from the key ring from its associated name.
    /// </summary>
    /// <param name="name">Name of the item to remove.</param>
    /// <returns>True if item was removed, false is it could not be found.</returns>
    public bool Remove(string name)
    {
        return _keyRing?.Remove(name) ?? false;
    }

    /// <summary>
    /// Removes all keys and identities in the key ring. The key ring will be empty after this call returns.
    /// </summary>
    public void Clear()
    {
        _keyRing?.Clear();
    }

    /// <summary>
    /// Returns a collection containing the names for the items stored in the key ring.
    /// </summary>
    /// <returns>A KeyCollection instance with all the names.</returns>
    public Dictionary<string, Item>.KeyCollection? Names()
    {
        return _keyRing?.Keys; 
    }

    /// <summary>
    /// Returns a collection containing the items in the key ring.
    /// </summary>
    /// <returns>A Value Collection instance with all the items.</returns>
    public Dictionary<string, Item>.ValueCollection? Items()
    {
        return _keyRing?.Values;
    }

    /// <summary>
    /// Imports all items in a DiME encoded envelope string to the key ring. If a verification key is provided then the
    /// signature of the envelope is first verified before any items are imported.
    /// </summary>
    /// <param name="encoded">The DiME encoded string with items that should be imported.</param>
    /// <param name="verifyKey">A key to verify the signature of the DiME encoded string, may be null to skip the verification.</param>
    /// <exception cref="IntegrityStateException">If signature verification failed, only if a verify key was provided.</exception>
    /// <exception cref="ArgumentException">If invalid items were provided.</exception>
    public void Import(string encoded, Key? verifyKey = null)
    {
        var envelope = Envelope.Import(encoded);
        if (verifyKey is null) return;
        var state = envelope.Verify(verifyKey);
        if (!Dime.IsIntegrityStateValid(state))
            throw new IntegrityStateException(state, "Unable to import key ring, unable to verify integrity.");
        foreach (var item in envelope.Items)
        {
            try
            {
                Put(item);
            }
            catch (ArgumentException)
            {
                throw new ArgumentException(
                    "Unable to import key ring, encoded envelope must only contain keys and identities.");
            }
        }
    }

    /// <summary>
    /// Returns a DiME encoded string of all items stored in the key ring. If a signing key is included then the
    /// returned DiME envelope will be signed by this key.
    /// </summary>
    /// <param name="signingKey">A key to sign the generated DiME envelope, may be null.</param>
    /// <returns> A DiME encoded string, null if the key ring is empty.</returns>
    public string? Export(Key? signingKey)
    {
        if (IsEmpty) return null;
        var envelope = new Envelope();
        foreach (var item in Items()!) // IsEmpty above checks for null value
            envelope.AddItem(item);
        if (signingKey is not null)
            envelope.Sign(signingKey);
        return envelope.Export();
    }

    public IntegrityState Verify(Item item)
    {
        if (Size == 0) {  return IntegrityState.FailedNoKeyRing; }
        var state = IntegrityState.FailedNotTrusted;
        foreach (var trustedItem in Items()!) // Size() above checks null state
        {
            state = trustedItem.VerifyDates(); // check so the trusted item is still within its validity period
            if (!Dime.IsIntegrityStateValid(state)) return state;
            var trustedKey = GetKey(trustedItem);
            if (trustedKey is null) return IntegrityState.FailedInternalFault;
            state = item.VerifySignature(trustedKey);
            if (state != IntegrityState.FailedKeyMismatch || item.IsLegacy)
                return state;
        }
        return state;
    }
    
    #endregion
    
    #region -- PRIVATE --

    private Dictionary<string, Item>? _keyRing;

    private static string? ItemName(Item item)
    {
        return item switch
        {
            Key key => Dime.Crypto.GenerateKeyIdentifier(key),
            Identity identity => identity.SubjectId.ToString().ToLower(),
            _ => null
        };
    }

    private static Key? GetKey(Item item)
    {
        return item switch
        {
            Key key => key,
            Identity identity => identity.PublicKey,
            _ => null
        };
    }
    
    #endregion

}