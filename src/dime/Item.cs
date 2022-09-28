//
//  Item.cs
//  Dime - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

#nullable enable
namespace DiME
{
    /// <summary>
    /// Base class for any other type of Dime items that can be included inside an Envelope instance.
    /// </summary>
    public abstract class Item
    {
        #region -- PUBLIC --

        /// <summary>
        /// Returns the tag of the Di:ME item. Must be overridden by any subclass.
        /// </summary>
        public abstract string Tag { get; }
        /// <summary>
        /// Returns a unique identifier for the instance. This will be generated at instance creation.
        /// </summary>
        public Guid UniqueId => (Guid) Claims().GetGuid(Claim.Uid);
        /// <summary>
        /// Returns the issuer's subject identifier. The issuer is the entity that has issued the identity to another
        /// entity. If this value is equal to the subject identifier, then this identity is self-issued.
        /// </summary>
        public Guid? IssuerId => Claims().GetGuid(Claim.Iss);
        /// <summary>
        /// The date and time when this Dime item was issued. Although, this date will most often be in the past, the
        /// item should not be processed if it is in the future.
        /// </summary>
        public DateTime? IssuedAt => Claims().GetDateTime(Claim.Iat);
        /// <summary>
        /// The date and time when the identity will expire, and should not be used and not trusted anymore.
        /// </summary>
        public DateTime? ExpiresAt => Claims().GetDateTime(Claim.Exp);
        /// <summary>
        /// Returns the context that is attached to the Dime item.
        /// </summary>
        public string? Context => Claims().Get<string>(Claim.Ctx);
        /// <summary>
        /// Checks if the item has been signed or not.
        /// </summary>
        public bool IsSigned { get; protected set; }
        /// <summary>
        /// Returns if the item is marked as legacy (compatible with Dime format before official version 1). 
        /// </summary>
        public bool IsLegacy { get; protected set; } = false;
        
        /// <summary>
        /// Will import an item from a Dime encoded string.Dime envelopes cannot be imported using this method, for
        /// envelopes use Envelope.importFromEncoded(String) instead.
        /// </summary>
        /// <param name="exported">The Dime encoded string to import an item from.</param>
        /// <typeparam name="T">The subclass of item of the imported Dime item.</typeparam>
        /// <returns>The imported Dime item.</returns>
        /// <exception cref="FormatException">If the encoded string is of a Dime envelope.</exception>
        public static T Import<T>(string exported) where T : Item, new()
        {
            var envelope = Envelope.Import(exported);
            if (envelope.Items is {Count: > 1})
            {
                throw new FormatException("Multiple items found, import as 'Envelope' instead.");
            }

            if (envelope.Items != null) return (T) envelope.Items.First();
            throw new NullReferenceException("Unable to import item, unexpected error occurred.");
        }

        /// <summary>
        /// Exports the item to a Dime encoded string.
        /// </summary>
        /// <returns>The Dime encoded representation of the item.</returns>
        public virtual string Export()
        {
            var envelope = new Envelope();
            envelope.AddItem(this);
            return envelope.Export();
        }

        /// <summary>
        /// Will sign an item with the proved key. The Key instance must contain a secret key and be of type IDENTITY.
        /// </summary>
        /// <param name="key">The key to sign the item with, must be of type IDENTITY.</param>
        /// <exception cref="InvalidOperationException"></exception>
        /// <exception cref="ArgumentNullException"></exception>
        public virtual void Sign(Key key)
        {
            if (IsLegacy && IsSigned)
                throw new InvalidOperationException("Unable to sign, legacy item is already signed.");
            if (key.Secret is null)
                throw new ArgumentNullException(nameof(key), "Unable to sign, key for signing must not be null.");
            if (IsSigned && Signature.Find(Dime.Crypto.GenerateKeyIdentifier(key), Signatures) is not null)
                throw new InvalidOperationException("Item already signed with provided key.");
            var signature = Dime.Crypto.GenerateSignature(Encode(false), key);
            var name = IsLegacy ? null : Dime.Crypto.GenerateKeyIdentifier(key);
            Signatures.Add(new Signature(signature, name));
            IsSigned = true;
        }

        /// <summary>
        ///  Will remove the signature of an item.
        /// </summary>
        /// <returns>True if the item was stripped of the signature, false otherwise.</returns>
        public bool strip()
        {
            Encoded = null;
            Components = null;
            _signatures = null;
            IsSigned = false;
            return true;
        }
        
        /// <summary>
        /// Returns the thumbprint of the item. This may be used to easily identify an item or detect if an item has
        /// been changed. This is created by securely hashing the item and will be unique and change as soon as any
        /// content changes.
        /// </summary>
        /// <returns>The hash of the item as a hex string.</returns>
        public virtual string Thumbprint()
        {
            return Thumbprint(Encode(true));
        }

        /// <summary>
        /// Returns the thumbprint of a Di:ME encoded item string. This may be used to easily identify an item or detect
        /// if an item has been changed. This is created by securely hashing the item and will be unique and change as
        /// soon as any content changes. This will generate the same value as the instance method thumbprint for the
        /// same (and unchanged) item.
        /// </summary>
        /// <param name="encoded">The Di:ME encoded item string.</param>
        /// <returns>The hash of the item as a hex string.</returns>
        public static string Thumbprint(string encoded)
        {
            return Utility.ToHex(Dime.Crypto.GenerateHash(Encoding.UTF8.GetBytes(encoded)));
        }

        /// <summary>
        /// Verifies the signature of the item using a provided key.
        /// </summary>
        /// <param name="key">The key to used to verify the signature, must not be null.</param>
        /// <exception cref="InvalidOperationException"></exception>
        public virtual void Verify(Key key)
        {
            if (!IsSigned)
                throw new InvalidOperationException("Unable to verify, item is not signed.");
            if (IsLegacy)
                Dime.Crypto.VerifySignature(Encode(false), Signatures[0].Bytes, key);
            else
            {
                var signature = Signature.Find(Dime.Crypto.GenerateKeyIdentifier(key), Signatures);
                if (signature is not null)
                    Dime.Crypto.VerifySignature(Encode(false), signature.Bytes, key);
                else
                    throw new IntegrityException("Unable to verify signature, item not signed with provided key.");
            }
        }

        /// <summary>
        /// Converts the item to legacy (compatible with earlier version of the Dime specification, before version 1)
        /// </summary>
        public virtual void ConvertToLegacy()
        {
            strip();
           IsLegacy = true;
        }

        #endregion

        #region -- INTERNAL --

        internal static Item? FromEncoded(string encoded)
        {
            var t = TypeFromTag(encoded[..encoded.IndexOf(Dime.ComponentDelimiter)]);
            if (t == null) return null;
            var item = (Item) Activator.CreateInstance(t)!;
            item.Decode(encoded);
            return item;
        }

        internal virtual string ForExport()
        {
            return Encode(true);
        }
        
        internal ClaimsMap Claims()
        {
            if (_claims is not null) return _claims;
            if (Components is not null && Components.Count > ComponentsClaimsIndex)
            {
                var jsonClaims = Utility.FromBase64(Components[ComponentsClaimsIndex]);
                _claims = new ClaimsMap(Encoding.UTF8.GetString(jsonClaims));
            }
            else
                _claims = new ClaimsMap();
            return _claims;
        }
        
        #endregion

        #region -- PROTECTED --

        /// <summary>The minimum number of components that must be present for a DiME item.</summary>
        protected const int MinimumNbrComponents = 2;
        /// <summary>The index number of the DiME item identifier string.</summary>
        protected const int ComponentsIdentifierIndex = 0;
        /// <summary>The index number of the DiME item claims.</summary>
        protected const int ComponentsClaimsIndex = 1;
        /// <summary>
        /// The encoded DiME item. Needs to remain intact once created or imported, this so thumbprints and signature
        /// verifications will be correct. 
        /// </summary>
        protected string? Encoded;
        /// <summary>A list of raw and encoded components of the DiME item.</summary>
        protected List<string>? Components;
        /// <summary>
        /// The signature of the Di:ME item, if any. Cannot be reproduced without the private key.
        /// </summary>
        //protected string? Signature;

        /// <summary>
        /// Indicates if an item has any claims attached to it.
        /// </summary>
        /// <returns>True if claims exists, false otherwise.</returns>
        protected bool HasClaims()
        {
            if (_claims is null && Components is not null)
                return Components.Count >= MinimumNbrComponents;
            return _claims is not null && _claims.size() > 0;
        }

        protected List<Signature> Signatures
        {
            get
            {
                if (_signatures is not null) return _signatures;
                _signatures = IsSigned ? Signature.FromEncoded(Components?[^1]) : new List<Signature>();
                return _signatures;
            }
        }

        /// <summary>
        /// Decodes an item. Abstract method that needs to be implemented in any subclass.
        /// </summary>
        /// <param name="encoded"></param>
        protected void Decode(string encoded)
        {
            var array = encoded.Split(new[] { Dime.ComponentDelimiter });
            if (array.Length < GetMinNbrOfComponents())
                throw new FormatException($"Unexpected number of components for Dime item, expected at least {GetMinNbrOfComponents()}, got {array.Length}.");
            if (!array[ComponentsIdentifierIndex].Equals(Tag)) throw new FormatException($"Unexpected Dime item identifier, expected: {Tag}, got {array[ComponentsClaimsIndex]}.");
            Components = new List<string>(array);
            CustomDecoding(Components);
            if (IsSigned)
            {
                IsLegacy = Signatures[0].IsLegacy;
                Encoded = encoded[..encoded.LastIndexOf(Dime.ComponentDelimiter)];
            }
            else
                Encoded = encoded;
        }

        /// <summary>
        /// Any additional decoding done by subclasses of Item.
        /// </summary>
        /// <param name="components">Components to decode.</param>
        protected abstract void CustomDecoding(List<string> components);

        /// <summary>
        /// Encodes an item and stores the result in Encoded. Abstract method that needs to be implemented in any
        /// subclass.
        /// </summary>
        /// <returns></returns>
        //protected abstract string Encode();

        protected virtual string Encode(bool withSignature)
        {
            if (Encoded is null)
            {
                var builder = new StringBuilder();
                CustomEncoding(builder);
                Encoded = builder.ToString();
            }
            if (withSignature && IsSigned)
            {
                return new StringBuilder()
                    .Append(Encoded)
                    .Append(Dime.ComponentDelimiter)
                    .Append(Signature.ToEncoded(Signatures))
                    .ToString();
            }
            return Encoded;
        }

        protected virtual void CustomEncoding(StringBuilder builder)
        {
            if (_claims is null) throw new FormatException("Unable to encode, item is missing claims.");
            builder.Append(Tag);
            builder.Append(Dime.ComponentDelimiter);
            builder.Append((Utility.ToBase64(_claims.ToJson())));    
        }

        protected virtual int GetMinNbrOfComponents() {
            return MinimumNbrComponents;
        }
        
        /// <summary>
        /// Checks if the Di:ME item is signed, and if it is, will throw an exception.
        /// </summary>
        /// <exception cref="InvalidOperationException">If the item is signed.</exception>
        protected void ThrowIfSigned() {
            if (IsSigned) { throw new InvalidOperationException("Unable to complete operation, Di:ME item already signed."); }
        }
        
        #endregion

        #region -- PRIVATE --

        private ClaimsMap? _claims;
        private List<Signature>? _signatures;
        
        private static Type? TypeFromTag(string tag)
        {
            return tag switch
            {
                Identity._TAG => typeof(Identity),
                IdentityIssuingRequest._TAG => typeof(IdentityIssuingRequest),
                Message._TAG => typeof(Message),
                Key._TAG => typeof(Key),
                _ => null
            };
        }
        
        #endregion
        
    }

}
