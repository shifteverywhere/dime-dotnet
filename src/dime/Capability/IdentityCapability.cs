//
//  IdentityCapability.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
namespace DiME.Capability;

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
    /// for a lower assurance level compared to 'Identify', or in cases where it is used purely for data integrity
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