//
//  KeyCapability.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
namespace DiME.Capability;
  
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