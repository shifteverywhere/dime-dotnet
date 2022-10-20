//
//  Exceptions.cs
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
/// Exception that is thrown if there is any problems with verifying the trust of an identity.
/// </summary>
[Serializable]
public class UntrustedIdentityException : Exception
{
    /// <summary>
    /// Create a new exception.
    /// </summary>
    public UntrustedIdentityException() { }
    /// <summary>
    /// Create a new exception with a description.
    /// </summary>
    /// <param name="message">A short description of what happened.</param>
    public UntrustedIdentityException(string message) : base(message) { }
    /// <summary>
    /// Create a new exception with a description and the underlying causing exception.
    /// </summary>
    /// <param name="message">A short description of what happened.</param>
    /// <param name="innerException">The causing exception.</param>
    public UntrustedIdentityException(string message, Exception innerException) : base(message, innerException) { }
    protected UntrustedIdentityException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}

/// <summary>
/// Exception that is thrown if there is any problems with verifying signatures.
/// </summary>
[Serializable]
public class IntegrityException : Exception
{
    /// <summary>
    /// Create a new exception.
    /// </summary>
    public IntegrityException() { }
    /// <summary>
    /// Create a new exception with a description.
    /// </summary>
    /// <param name="message">A short description of what happened.</param>
    public IntegrityException(string message) : base(message) { }
    /// <summary>
    /// Create a new exception with a description and the underlying causing exception.
    /// </summary>
    /// <param name="message">A short description of what happened.</param>
    /// <param name="innerException">The causing exception.</param>
    public IntegrityException(string message, Exception innerException) : base(message, innerException) { }
    protected IntegrityException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}

/// <summary>
/// Exception that is thrown if there is any problems with dates stored inside a Di:ME.  This may happen if an
/// identity has expired, or if an issued at date is later than an expired at date.
/// </summary>
[Serializable]
public class DateExpirationException : Exception
{
    /// <summary>
    /// Create a new exception.
    /// </summary>
    public DateExpirationException() { }
    /// <summary>
    /// Create a new exception with a description.
    /// </summary>
    /// <param name="message">A short description of what happened.</param>
    public DateExpirationException(string message) : base(message) { }
    /// <summary>
    /// Create a new exception with a description and the underlying causing exception.
    /// </summary>
    /// <param name="message">A short description of what happened.</param>
    /// <param name="innerException">The causing exception.</param>
    public DateExpirationException(string message, Exception innerException) : base(message, innerException) { }
    protected DateExpirationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}

/// <summary>
/// Exception that is thrown if there is any mismatch between keys provided to a  method. This may happen when using
/// a key of the wrong type.
/// </summary>
[Serializable]
public class KeyMismatchException : Exception
{
    /// <summary>
    /// Create a new exception.
    /// </summary>
    public KeyMismatchException() { }
    /// <summary>
    /// Create a new exception with a description.
    /// </summary>
    /// <param name="message">A short description of what happened.</param>
    public KeyMismatchException(string message) : base(message) { }
    /// <summary>
    /// Create a new exception with a description and the underlying causing exception.
    /// </summary>
    /// <param name="message">A short description of what happened.</param>
    /// <param name="innerException">The causing exception.</param>
    public KeyMismatchException(string message, Exception innerException) : base(message, innerException) { }
    protected KeyMismatchException(SerializationInfo info, StreamingContext context) : base(info, context) { }
}
