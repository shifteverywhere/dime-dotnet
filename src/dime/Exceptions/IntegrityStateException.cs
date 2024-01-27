//
//  IntegrityStateException.cs
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
using System;
using DiME.KeyRing;

namespace DiME.Exceptions;

/// <summary>
/// Exception that is thrown if there is any problems with verifying the integrity of an item. Is used in those cases
/// where it is not possible to return an instance of IntegrityState.
/// </summary>
[Serializable]
public class IntegrityStateException: Exception
{

    /// <summary>
    /// The integrity state fault that caused the exception.
    /// </summary>
    public IntegrityState State { get; private set; }

    /// <summary>
    /// Create a new exception with the causing integrity state and exception message.
    /// </summary>
    /// <param name="state">The Integrity state that caused the exception.</param>
    /// <param name="message">A short description of what happened.</param>
    public IntegrityStateException(IntegrityState state, string message) : base(message)
    {
        State = state;
    }
    
}