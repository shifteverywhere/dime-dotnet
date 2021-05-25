using System;
using System.Runtime.Serialization;

namespace ShiftEverywhere.DiME
{
    [Serializable]
    public class UnsupportedKeyTypeException : Exception
    {
        public UnsupportedKeyTypeException() : base() { }
        public UnsupportedKeyTypeException(string message) : base(message) { }
        public UnsupportedKeyTypeException(string message, Exception innerException) : base(message, innerException) { }
        public UnsupportedKeyTypeException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class UnsupportedProfileException : Exception
    {
        public UnsupportedProfileException() : base() { }
        public UnsupportedProfileException(string message) : base(message) { }
        public UnsupportedProfileException(string message, Exception innerException) : base(message, innerException) { }
        public UnsupportedProfileException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class UntrustedIdentityException : Exception
    {
        public UntrustedIdentityException() : base() { }
        public UntrustedIdentityException(string message) : base(message) { }
        public UntrustedIdentityException(string message, Exception innerException) : base(message, innerException) { }
        public UntrustedIdentityException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class IntegrityException : Exception
    {
        public IntegrityException() : base() { }
        public IntegrityException(string message) : base(message) { }
        public IntegrityException(string message, Exception innerException) : base(message, innerException) { }
        public IntegrityException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class DateExpirationException : Exception
    {
        public DateExpirationException() : base() { }
        public DateExpirationException(string message) : base(message) { }
        public DateExpirationException(string message, Exception innerException) : base(message, innerException) { }
        public DateExpirationException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class KeyMissmatchException : Exception
    {
        public KeyMissmatchException() : base() { }
        public KeyMissmatchException(string message) : base(message) { }
        public KeyMissmatchException(string message, Exception innerException) : base(message, innerException) { }
        public KeyMissmatchException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class ImmutableException : Exception
    {
        public ImmutableException() : base() { }
        public ImmutableException(string message) : base(message) { }
        public ImmutableException(string message, Exception innerException) : base(message, innerException) { }
        public ImmutableException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class IdentityCapabilityException : Exception
    {
        public IdentityCapabilityException() : base() { }
        public IdentityCapabilityException(string message) : base(message) { }
        public IdentityCapabilityException(string message, Exception innerException) : base(message, innerException) { }
        public IdentityCapabilityException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

    [Serializable]
    public class DataFormatException : Exception
    {
        public DataFormatException() : base() { }
        public DataFormatException(string message) : base(message) { }
        public DataFormatException(string message, Exception innerException) : base(message, innerException) { }
        public DataFormatException(SerializationInfo info, StreamingContext context) : base(info, context) { }
    }

}