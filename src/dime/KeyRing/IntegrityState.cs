//
//  IntegrityState.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
namespace DiME.KeyRing;

/// <summary>
///  Holds the result from an item verification, i.e. using Item.Verify() or related methods.
/// </summary>
public enum IntegrityState
{
    /// <summary>The integrity of the item was verified successfully, item can be trusted.</summary>
    Complete,
    /// <summary>Signature validated is correct and item is intact (data integrity).</summary>
    ValidSignature,
    /// <summary>Dates validated are correct and item within its validity period.</summary>
    ValidDates,
    /// <summary>Item links validated are correct.</summary>
    ValidItemLinks,
    /// <summary>Signature is missing from the item being verified.</summary>
    FailedNoSignature,
    /// <summary>The item could not be verified to be trusted.</summary>
    FailedNotTrusted,
    /// <summary>The key or keys used to verify the item does not match any signatures in that item.</summary>
    FailedKeyMismatch,
    /// <summary>The issuer id of the item does not match the subject id of the identity used for verification.</summary>
    FailedIssuerMismatch,
    /// <summary>The item verified has passed its own expiration date and should not be used or trusted.</summary>
    FailedUsedAfterExpired,
    /// <summary>The item verified has not yet passed its issued at date and should not yet be used.</summary>
    FailedUsedBeforeIssued,
    /// <summary>There is a mismatch in the expires at and issued at dates in the item. Item should not be used or trusted.</summary>
    FailedDateMismatch,
    /// <summary>Any or all linked items could not be verified successfully. Full integrity of the item could not be verified, should not be trusted.</summary>
    FailedLinkedItemFault,
    /// <summary>There is a mismatch in item links and provided items.</summary>
    FailedLinkedItemMismatch,
    /// <summary>No linked items found, so verification could not be completed.</summary>
    FailedLinkedItemMissing,
    /// <summary>An invalid item was encountered in the key ring, so verification could not be completed.</summary>
    FailedInvalidKeyRingItem,
    /// <summary>There are no keys or identities stored in the key rings, so verification could not be done.</summary>
    FailedNoKeyRing,
    /// <summary>Verification encountered an unexpected internal error which could not be recovered from.</summary>
    FailedInternalFault
    
}