//
//  Claim.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
namespace DiME;

/// <summary>
/// Standard claim names.
/// </summary>
public enum Claim
{
    /// <summary>Ambit</summary>
    Amb,
    /// <summary>Audience</summary>
    Aud,
    /// <summary>Capability</summary>
    Cap,
    /// <summary>Context</summary>
    Ctx,
    /// <summary>Expires at</summary>
    Exp,
    /// <summary>Issued at</summary>
    Iat,
    /// <summary>Issuer</summary>
    Iss,
    /// <summary>Key</summary>
    Key,
    /// <summary>Key ID</summary>
    Kid,
    /// <summary>Link</summary>
    Lnk,
    /// <summary>Method</summary>
    Mtd,
    /// <summary>MIME Type</summary>
    Mim,
    /// <summary>Public key</summary>
    Pub,
    /// <summary>Principle</summary>
    Pri,
    /// <summary>Subject</summary>
    Sub,
    /// <summary>System</summary>
    Sys,
    /// <summary>Unique ID</summary>
    Uid

}