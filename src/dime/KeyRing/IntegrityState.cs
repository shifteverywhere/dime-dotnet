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
    /// <summary>All parts of the DiME item was successfully verified and the item may be trusted.</summary>
    Complete,
    /// <summary>All parts of the DiME item was successfully verified. However, not all linked items where verified, although, those that where was successful.</summary>
    PartiallyComplete,
    /// <summary> All verified parts of the DiME item was successful. However, some parts where skipped, like linked items as no list of items where provided. </summary>
    Intact,
    /// <summary>The signature of the DiME item was verified successfully. No other parts where verified.</summary>
    ValidSignature,
    /// <summary>The dates (issued at and/or expires at) in the DiME item were verified successfully. No other parts where verified.</summary>
    ValidDates,
    /// <summary>Any linked items where verified successfully against a provided item list. No items where skipped or missing. No other parts where verified.</summary>
    ValidItemLinks,
    /// <summary>All linked items where verified successfully against a provided item list. Any list, linked items or provided items, may contain items not in the other list. No other parts where verified.</summary>
    PartiallyValidItemLinks,
    /// <summary>Unable to verify the digital signature, as the DiME item did not contain a signature.</summary>
    FailedNoSignature,
    /// <summary>The digital signature could not be successfully verified, and, thus the DiME item must not be trusted.</summary>
    FailedNotTrusted,
    /// <summary>The public key used to verify the DiME item does not match the key pair used to generate the digital signature.</summary>
    FailedKeyMismatch,
    /// <summary>The issuer ID ("iss") in the DiME identity used when verifying does not match issuer ID ("iss") set in the item verified.</summary>
    FailedIssuerMismatch,
    /// <summary>The expiration date ("exp") set in the DiME item verified has passed, and the item should no longer be used.</summary>
    FailedUsedAfterExpired,
    /// <summary>The issued at date ("iat") set in the DiME item has not yet passed, and the item should not be used yet.</summary>
    FailedUsedBeforeIssued,
    /// <summary>The dates set in the DiME item verified are incorrect, where the issued at date ("iat") is after the expiration date ("exp").</summary>
    FailedDateMismatch,
    /// <summary>One, or several, linked items could not be verified successfully.</summary>
    FailedLinkedItemFault,
    /// <summary>Provided item list to verify linked items contains additional, non-linked, items.</summary>
    FailedLinkedItemMismatch,
    /// <summary>No linked items found when verifying with a provided item list.</summary>
    FailedLinkedItemMissing,
    /// <summary>An invalid item was encountered in the key ring, so verification could not be completed.</summary>
    FailedInvalidKeyRingItem,
    /// <summary>There are no keys or identities stored in the key rings, so verification could not be done.</summary>
    FailedNoKeyRing,
    /// <summary>Verification encountered an unexpected internal error which could not be recovered from.</summary>
    FailedInternalFault
    
}