//
//  Enums.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
namespace ShiftEverywhere.DiME
{
    /// <summary>List capabilities that can be associated with a DiME identity object. These define
    /// what an identity can be used for.</summary>
    public enum Capability
    {
        /// <summary>Capability set if the identity has been self signed. This capability often indicates
        /// a root identity, the start of a trust chain.</summary>
        Self, 
        /// <summary>A generic capability, may have been set after a simple registration. Depending on the
        /// applicaiton, the identity may have limited usage.</summary>
        Generic, 
        /// <summary>A capability that indicates that the identity have been verified and is associated with
        /// a higher level of assurance. This may be done through more in-depth registration or secondary 
        ///verification.</summary>
        Identify, 
        /// <summary>This capability allows an identity to sign and issue other identities, thus creating leaf
        /// identities in a trust chain. A root identity does often have this capability. However it may be
        /// assigned to other identities further down in a trust chain.</summary>
        Issue
    }

    /// <summary>The cryptographic profile used for a DiME object. Currently
    /// only Uno (0x01) is supported.</summary>
    public enum Profile : byte
    {
        /// <summary>Undefined profile, used when a profile wasn't set properly, for errors.</summary>
        Undefined = 0x00,
        /// <summary>First generation cryptographic profile. Ed25519 for identity keys, 
        /// X25519 for key exchange (agreement), Blake2b-256 for hashes, and XYZ for encryption.</summary>
        Uno = 0x01
    }

    /// <summary>Defines diffrent types of cryptographic keys.</summary>
    public enum KeyType : byte
    {
        Undefined = 0x00,
        /// <summary>Key type for asymmetric key used for signing.</summary>
        Identity = 0x10,
        /// <summary>Key type for asymmetric keys used for key exchange (agreement).</summary>
        Exchange = 0x20,
        /// <summary>Key type for secret (symmetric) keys, used for encryption.
        Secret = 0xE0,
        Shared = 0xF0
    }

    public enum KeyVariant: byte
    {
        Private = 0x00,
        Public = 0x01
    }

}