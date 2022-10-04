//
//  Enums.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
namespace DiME;

public enum KeyIndex
{
    SecretKey = 0,
    PublicKey = 1
}
   
/// <summary>
/// Defines different types of cryptographic keys.
/// Used for header information in keys and when generating new keys.
/// </summary>
public enum KeyCapability
{
    /// <summary>
    /// Undefined usage of the key (should not happen).
    /// </summary>
    Undefined,
    /// <summary>
    /// Key type for asymmetric key used for signing.
    /// </summary>
    Sign,
    /// <summary>
    /// Key type for asymmetric keys used for key exchange (agreement).
    /// </summary>
    Exchange,
    /// <summary>
    /// Key type for symmetric keys used for encryption.
    /// </summary>
    Encrypt
}

/// <summary>
/// Defines the family a particular algorithm belongs to. Used for header information in keys.
/// </summary>
public enum AlgorithmFamily
{
    /// <summary>
    /// Undefined algorithm.
    /// </summary>
    Undefined = 0x00,

    /// <summary>
    /// Symmetric authentication encryption algorithm.
    /// </summary>
    Aead = 0x10,

    /// <summary>
    /// Asymmetric Elliptic Curve key agreement algorithm.
    /// </summary>
    Ecdh = 0x40,

    /// <summary>
    /// Asymmetric Edwards-curve digital signature algorithm
    /// </summary>
    Eddsa = 0x80,

    /// <summary>
    /// Secure hashing algorithm.
    /// </summary>
    Hash = 0xE0
}

/// <summary>
/// Defines the capability or capabilities of an identity. This usually relates to what an identity may be used for.
/// </summary>
public enum IdentityCapability
{
    /// <summary>
    /// Capability set if the identity has been self signed. This capability often indicates a root identity, the
    /// start of a trust chain.
    /// </summary>
    Self,
    /// <summary>
    /// A generic capability, may have been set after a simple registration. Depending on the application, the
    /// identity may have limited usage.
    /// </summary>
    Generic,
    /// <summary>
    /// A capability that indicates that the identity have been verified and is associated with a higher level of
    /// assurance. This may be done through more in-depth registration or secondary verification.
    /// </summary>
    Identify,
    /// <summary>
    /// A capability that indicates that the identity can be used to prove ownership of something. Intended to be used
    /// for a lower assurance level compared to IDENTIFY, or in cases where it is used purely for data integrity
    /// protection.
    /// </summary>
    Prove,
    /// <summary>
    /// This capability allows an identity to sign and issue other identities, thus creating leaf identities in a
    /// trust chain. A root identity does often have this capability. However, it may be assigned to other
    /// identities further down in a trust chain.
    /// </summary>
    Issue
    
}

/// <summary>
/// Defines different types of cryptographic keys. Used for header information in keys and when generating new keys.
/// </summary>
public enum KeyType : byte
{
    /// <summary>
    /// Undefined usage of the key (should not happen).
    /// </summary>
    Undefined = 0x00,

    /// <summary>
    /// Key type for asymmetric key used for signing.
    /// </summary>
    Identity = 0x10,

    /// <summary>
    /// Key type for asymmetric keys used for key exchange (agreement).
    /// </summary>
    Exchange = 0x20,

    /// <summary>
    /// Key type for secret (symmetric) keys, used for encryption.
    /// </summary>
    Encryption = 0xE0,

    /// <summary>
    /// Key type for symmetric keys used for message authentication.
    /// </summary>
    Authentication = 0xF0
}

/// <summary>
/// Defines rhe variant of a key, may either be Secret or Public. Used for header information in keys.
/// </summary>
public enum KeyVariant : byte
{
    /// <summary>
    /// Secret keying material. If a key is marked with Secret, then it should never be stored or transmitted as
    /// plain text.
    /// </summary>
    Secret = 0x00,

    /// <summary>
    /// Public keying material. Keys marked as PUBLIC can safely be distributed and shared with other parties.
    /// </summary>
    Public = 0x01
}

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