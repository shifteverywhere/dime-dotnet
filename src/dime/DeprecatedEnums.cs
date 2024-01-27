//
//  Enums.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
using System;

namespace DiME;
  
/// <summary>
/// Defines the family a particular algorithm belongs to. Used for header information in keys.
/// </summary>
[Obsolete("Legacy, do not use.")]
internal enum AlgorithmFamily
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
/// Defines different types of cryptographic keys. Used for header information in keys and when generating new keys.
/// </summary>
/// [Obsolete("Legacy, do not use.")]
internal enum KeyType : byte
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
