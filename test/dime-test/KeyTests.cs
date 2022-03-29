//
//  KeyTests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Linq;
using DiME;

namespace DiME_test
{
    [TestClass]
    public class KeyTests
    {
        
        [TestMethod]
        public void GetTagTest1() {
            var key = Key.Generate(KeyType.Identity);
            Assert.AreEqual("KEY", key.Tag);
        }
        
        [TestMethod]
        public void KeyTest1()
        {
            var key = Key.Generate(KeyType.Identity);
            Assert.IsTrue(key.Type == KeyType.Identity);
            Assert.IsNotNull(key.UniqueId);
            Assert.IsNotNull(key.Public);
            Assert.IsNotNull(key.Secret);
        }

        [TestMethod]
        public void KeyTest2()
        {
            var key = Key.Generate(KeyType.Exchange);
            Assert.IsTrue(key.Type == KeyType.Exchange);
            Assert.IsNotNull(key.UniqueId);
            Assert.IsNotNull(key.Public);
            Assert.IsNotNull(key.Secret);
        }

        [TestMethod]
        public void ExportTest1()
        {
            var key = Key.Generate(KeyType.Identity);
            var encoded = key.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.StartsWith($"{Envelope._HEADER}:{Key._TAG}"));
            Assert.IsTrue(encoded.Split(".").Length == 2);
        }

        [TestMethod]
        public void ImportTest1()
        {
            const string encoded = "Di:KEY.eyJ1aWQiOiI3ZmE2OGU4OC02ZDVjLTQwMmItOThkOC1mZDg2NjQwY2Y0ZjIiLCJpYXQiOiIyMDIxLTEyLTAxVDIwOjUzOjIzLjM4MzczM1oiLCJrZXkiOiIyVERYZDlXVXR3dVliaTROaFNRRUhmTjg5QmhLVkNTQWVqUFpmRlFRZ1BxaVJadXNUTkdtcll0ZVEiLCJwdWIiOiIyVERYZG9OdXNiNXlWQXB6WTIzYXR1UTNzbUdiOExuZ0o0QVpYRWhpck1mQ0t5OHFkNEZwM1c5OHMifQ";
            var key = Item.Import<Key>(encoded);
            Assert.AreEqual(KeyType.Identity, key.Type);
            Assert.AreEqual(new Guid("7fa68e88-6d5c-402b-98d8-fd86640cf4f2"), key.UniqueId);
            Assert.AreEqual(DateTime.Parse("2021-12-01T20:53:23.383733Z").ToUniversalTime(), key.IssuedAt);
            Assert.AreEqual("2TDXd9WUtwuYbi4NhSQEHfN89BhKVCSAejPZfFQQgPqiRZusTNGmrYteQ", key.Secret);
            Assert.AreEqual("2TDXdoNusb5yVApzY23atuQ3smGb8LngJ4AZXEhirMfCKy8qd4Fp3W98s", key.Public);
        }

        [TestMethod]
        public void PublicOnlyTest1()
        {
            var key = Key.Generate(KeyType.Identity, 120, Guid.NewGuid(), "Racecar is racecar backwards.");
            Assert.IsNotNull(key.Secret);
            var pubOnly = key.PublicCopy();
            Assert.IsNull(pubOnly.Secret);
            Assert.AreEqual(key.Public, pubOnly.Public);
            Assert.AreEqual(key.UniqueId, pubOnly.UniqueId);
            Assert.AreEqual(key.IssuedAt, pubOnly.IssuedAt);
            Assert.AreEqual(key.ExpiresAt, pubOnly.ExpiresAt);
            Assert.AreEqual(key.IssuerId, pubOnly.IssuerId);
            Assert.AreEqual(key.Context, pubOnly.Context);
        }

        [TestMethod]
        public void PublicOnlyTest2()
        {
            var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            var pubOnly = Commons.IssuerKey.PublicCopy();
            message.Verify(pubOnly);            
        }

        [TestMethod]
        public void KeyHeaderTest1() {
            var aeadHeader = new[] { (byte)Envelope._DIME_VERSION, (byte)0x10, (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00 }; // version 1, AEAD, XChaCha20-Poly1305, 256-bit, extension, extension
            var aead = Key.Generate(KeyType.Encryption);
            Assert.IsNull(aead.Public);
            var bytes = Base58.Decode(aead.Secret);
            Assert.IsNotNull(bytes);
            var header = Utility.SubArray(bytes, 0, 6);
            Assert.IsTrue(aeadHeader.SequenceEqual(header));
        }

        [TestMethod]
        public void KeyHeaderTest2() {
            var ecdhHeaderSecret = new[] { (byte)Envelope._DIME_VERSION, (byte)0x40, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00 }; // version 1, ECDH, X25519, public, extension, extension
            var ecdhHeaderPublic = new[] { (byte)Envelope._DIME_VERSION, (byte)0x40, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x00 }; // version 1, ECDH, X25519, private, extension, extension
            var ecdh = Key.Generate(KeyType.Exchange);
            var bytesSecret = Base58.Decode(ecdh.Secret);
            var bytesPublic = Base58.Decode(ecdh.Public);
            Assert.IsNotNull(bytesSecret);
            Assert.IsNotNull(bytesPublic);
            var headerSecret = Utility.SubArray(bytesSecret, 0, 6);
            var headerPublic = Utility.SubArray(bytesPublic, 0, 6);
            Assert.IsTrue(ecdhHeaderSecret.SequenceEqual(headerSecret));
            Assert.IsTrue(ecdhHeaderPublic.SequenceEqual(headerPublic));
        }

        [TestMethod]
        public void KeyHeaderTest3() {
            var eddsaHeaderSecret = new[] { (byte)Envelope._DIME_VERSION, (byte)0x80, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00 }; // version 1, EdDSA, Ed25519, public, extension, extension
            var eddsaHeaderPublic = new[] { (byte)Envelope._DIME_VERSION, (byte)0x80, (byte)0x01, (byte)0x01, (byte)0x00, (byte)0x00 }; // version 1, EdDSA, Ed25519, private, extension, extension
            var eddsa = Key.Generate(KeyType.Identity);
            var bytesSecret = Base58.Decode(eddsa.Secret);
            var bytesPublic = Base58.Decode(eddsa.Public);
            Assert.IsNotNull(bytesSecret);
            Assert.IsNotNull(bytesPublic);
            var headerSecret = Utility.SubArray(bytesSecret, 0, 6);
            var headerPublic = Utility.SubArray(bytesPublic, 0, 6);
            Assert.IsTrue(eddsaHeaderSecret.SequenceEqual(headerSecret));
            Assert.IsTrue(eddsaHeaderPublic.SequenceEqual(headerPublic));
        }

        [TestMethod]
        public void KeyHeaderTest4() {
            var hashHeader = new[] { (byte)Envelope._DIME_VERSION, (byte)0xE0, (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00 }; // version 1, Secure Hashing, Blake2b, 256-bit, extension, extension
            var hash = Key.Generate(KeyType.Authentication);
            Assert.IsNull(hash.Public);
            var bytes = Base58.Decode(hash.Secret);
            Assert.IsNotNull(bytes);
            var header = Utility.SubArray(bytes, 0, 6);
            Assert.IsTrue(hashHeader.SequenceEqual(header));
        }

        [TestMethod]
        public void ContextTest1() {
            const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            var key = Key.Generate(KeyType.Identity, context);
            Assert.AreEqual(context, key.Context);
        }

        [TestMethod]
        public void ContextTest2() {
            const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            var key1 = Key.Generate(KeyType.Identity, context);
            var exported = key1.Export();
            var key2 = Item.Import<Key>(exported);
            Assert.AreEqual(context, key2.Context);
        }

        [TestMethod]
        public void ContextTest3() {
            const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
            try {
                Key.Generate(KeyType.Identity, context);
            } catch (ArgumentException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

    }
}