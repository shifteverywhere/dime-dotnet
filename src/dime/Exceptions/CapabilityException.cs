//
//  CapabilityException.cs
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Runtime.Serialization;

namespace DiME.Exceptions;

/// <summary>
/// Exception that is thrown if there is any problems with capabilities for a DiME item. This may, for example, happen
/// when trying to issue a new identity and the identity issuing request (IIR) contains more capabilities than allowed.
/// It may also happen when an identity that is missing the 'Issue' capability is trying to issue a new identity from an IIR.
/// </summary>
[Serializable]
public class CapabilityException : Exception
{
    /// <summary>
    /// Create a new exception.
    /// </summary>
    public CapabilityException() { }
    /// <summary>
    /// Create a new exception with a description.
    /// </summary>
    /// <param name="message">A short description of what happened.</param>
    public CapabilityException(string message) : base(message) { }
    /// <summary>
    /// Create a new exception with a description and the underlying causing exception.
    /// </summary>
    /// <param name="message">A short description of what happened.</param>
    /// <param name="innerException">The causing exception.</param>
    public CapabilityException(string message, Exception innerException) : base(message, innerException) { }
    /// <summary>
    /// Initializes a new instance of the CapabilityException class with serialized data.
    /// </summary>
    /// <param name="info">Holds the serialized object data about the exception being thrown.</param>
    /// <param name="context">Contains contextual information about the source or destination.</param>
    protected CapabilityException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}