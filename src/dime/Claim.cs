//
//  Claim.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
namespace DiME;

/// <summary>
/// Standard claim names.
/// </summary>
public enum Claim
{
    /// <summary>Ambit - Describes the region, location or boundaries where the item is intended or valid (All).</summary>
    Amb,
    /// <summary>Audience ID - The identifier of the indented receiver, or audience, of the item (All).</summary>
    Aud,
    /// <summary>Capability - Describes the capabilities, or usages/constrains, of an item (Identity, Identity Issuing
    /// Request, Key).</summary>
    Cap,
    /// <summary>Common Name - A common name, or alias, for the item, may be used to simplify manual identification of items (All).</summary>
    Cmn,
    /// <summary>Context - The context for in which the item is to be used or valid (All).</summary>
    Ctx,
    /// <summary>Expires at - The date and time when the item should be considered invalid and should no longer be used
    /// (All).</summary>
    Exp,
    /// <summary>Issued at - The date and time when the item should be considered valid and only used after (until
    /// expires at, if specified) (All).</summary>
    Iat,
    /// <summary>Issuer ID - The identifier of the issuer of the item (All).</summary>
    Iss,
    /// <summary>Issuer URL - A URL or other form of resource locator where the issuer identity or public key may be
    /// fetched (All).</summary>
    Isu,
    /// <summary>Secret key - A secret key in raw format, may be a private key or a shared key (Key).</summary>
    Key,
    /// <summary>Key ID - The identifier of a key that is related to the item (All).</summary>
    Kid,
    /// <summary>Item links - Item links to other items that has been securely linked to the item (All).</summary>
    Lnk,
    /// <summary>MIME type - The MIME type of any payload that is attached to the item (Data, Message).</summary>
    Mim,
    /// <summary>Method- Intended for use with external systems and data formats. Will be specified further in the
    /// future (All).</summary>
    Mtd,
    /// <summary>Public key - A public key in raw format (Identity, Identity Issuing Request, Key, Message).</summary>
    Pub,
    /// <summary>Principle information - A key-value object with further information related to the principle related to
    /// the item (Identity, Identity Issuing Request).</summary>
    Pri,
    /// <summary>Subject ID - The identifier of the subject related to the item (All).</summary>
    Sub,
    /// <summary>System name - The name of the system where the item originated from or belongs to (All).</summary>
    Sys,
    /// <summary>Unique ID - A unique identifier for the item (All).</summary>
    Uid

}