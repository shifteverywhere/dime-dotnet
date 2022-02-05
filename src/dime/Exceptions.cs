//
//  Exceptions.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Runtime.Serialization;

namespace ShiftEverywhere.DiME
{

    [Serializable]
    public class UntrustedIdentityException : Exception
    {
        public UntrustedIdentityException() { }
        public UntrustedIdentityException(string message) : base(message) { }
        public UntrustedIdentityException(string message, Exception innerException) : base(message, innerException) { }
        protected UntrustedIdentityException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class IntegrityException : Exception
    {
        public IntegrityException() { }
        public IntegrityException(string message) : base(message) { }
        public IntegrityException(string message, Exception innerException) : base(message, innerException) { }
        protected IntegrityException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class DateExpirationException : Exception
    {
        public DateExpirationException() { }
        public DateExpirationException(string message) : base(message) { }
        public DateExpirationException(string message, Exception innerException) : base(message, innerException) { }
        protected DateExpirationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class KeyMismatchException : Exception
    {
        public KeyMismatchException() { }
        public KeyMismatchException(string message) : base(message) { }
        public KeyMismatchException(string message, Exception innerException) : base(message, innerException) { }
        protected KeyMismatchException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class IdentityCapabilityException : Exception
    {
        public IdentityCapabilityException() { }
        public IdentityCapabilityException(string message) : base(message) { }
        public IdentityCapabilityException(string message, Exception innerException) : base(message, innerException) { }
        protected IdentityCapabilityException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

}