//
//  KeyTests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Linq;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class KeyTests
    {
        [TestMethod]
        public void KeyTest1()
        {
            Key key = Key.Generate(KeyType.Identity);
            Assert.IsTrue(key.Type == KeyType.Identity);
            Assert.IsNotNull(key.UniqueId);
            Assert.IsNotNull(key.Public);
            Assert.IsNotNull(key.Secret);
        }

        [TestMethod]
        public void KeyTest2()
        {
            Key key = Key.Generate(KeyType.Exchange);
            Assert.IsTrue(key.Type == KeyType.Exchange);
            Assert.IsNotNull(key.UniqueId);
            Assert.IsNotNull(key.Public);
            Assert.IsNotNull(key.Secret);
        }

        [TestMethod]
        public void ExportTest1()
        {
            Key key = Key.Generate(KeyType.Identity);
            string encoded = key.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.StartsWith($"{Envelope.HEADER}:{Key.TAG}"));
            Assert.IsTrue(encoded.Split(".").Length == 2);
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded = "Di:KEY.eyJ1aWQiOiI3ZmE2OGU4OC02ZDVjLTQwMmItOThkOC1mZDg2NjQwY2Y0ZjIiLCJpYXQiOiIyMDIxLTEyLTAxVDIwOjUzOjIzLjM4MzczM1oiLCJrZXkiOiIyVERYZDlXVXR3dVliaTROaFNRRUhmTjg5QmhLVkNTQWVqUFpmRlFRZ1BxaVJadXNUTkdtcll0ZVEiLCJwdWIiOiIyVERYZG9OdXNiNXlWQXB6WTIzYXR1UTNzbUdiOExuZ0o0QVpYRWhpck1mQ0t5OHFkNEZwM1c5OHMifQ";
            Key key = Item.Import<Key>(encoded);
            Assert.AreEqual(KeyType.Identity, key.Type);
            Assert.AreEqual(new Guid("7fa68e88-6d5c-402b-98d8-fd86640cf4f2"), key.UniqueId);
            Assert.AreEqual(DateTime.Parse("2021-12-01T20:53:23.383733Z").ToUniversalTime(), key.IssuedAt);
            Assert.AreEqual("2TDXd9WUtwuYbi4NhSQEHfN89BhKVCSAejPZfFQQgPqiRZusTNGmrYteQ", key.Secret);
            Assert.AreEqual("2TDXdoNusb5yVApzY23atuQ3smGb8LngJ4AZXEhirMfCKy8qd4Fp3W98s", key.Public);
        }

        [TestMethod]
        public void PublicOnlyTest1()
        {
            Key key = Key.Generate(KeyType.Identity, -1);
            Assert.IsNotNull(key.Secret);
            Key pubOnly = key.PublicCopy();
            Assert.IsNull(pubOnly.Secret);
            Assert.AreEqual(key.UniqueId, pubOnly.UniqueId);
        }

        [TestMethod]
        public void PublicOnlyTest2()
        {
            Key key = Key.Generate(KeyType.Identity, -1);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            Key pubOnly = Commons.IssuerKey.PublicCopy();
            message.Verify(pubOnly);            
        }

        [TestMethod]
        public void KeyHeaderTest1() {
            byte[] aeadHeader = new byte[] { (byte)Envelope.DIME_VERSION, (byte)0x10, (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00 }; // version 1, AEAD, XChaCha20-Poly1305, 256-bit, extension, extension
            Key aead = Key.Generate(KeyType.Encryption);
            Assert.IsNull(aead.Public);
            byte[] bytes = Base58.Decode(aead.Secret);
            Assert.IsNotNull(bytes);
            byte[] header = Utility.SubArray(bytes, 0, 6);
            Assert.IsTrue(aeadHeader.SequenceEqual(header));
        }

        [TestMethod]
        public void KeyHeaderTest2() {
            byte[] ecdhHeaderSecret = new byte[] { (byte)Envelope.DIME_VERSION, (byte)0x40, (byte)0x02, (byte)0x00, (byte)0x00, (byte)0x00 }; // version 1, ECDH, X25519, public, extension, extension
            byte[] ecdhHeaderPublic = new byte[] { (byte)Envelope.DIME_VERSION, (byte)0x40, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x00 }; // version 1, ECDH, X25519, private, extension, extension
            Key ecdh = Key.Generate(KeyType.Exchange);
            byte[] bytesSecret = Base58.Decode(ecdh.Secret);
            byte[] bytesPublic = Base58.Decode(ecdh.Public);
            Assert.IsNotNull(bytesSecret);
            Assert.IsNotNull(bytesPublic);
            byte[] headerSecret = Utility.SubArray(bytesSecret, 0, 6);
            byte[] headerPublic = Utility.SubArray(bytesPublic, 0, 6);
            Assert.IsTrue(ecdhHeaderSecret.SequenceEqual(headerSecret));
            Assert.IsTrue(ecdhHeaderPublic.SequenceEqual(headerPublic));
        }

        [TestMethod]
        public void KeyHeaderTest3() {
            byte[] eddsaHeaderSecret = new byte[] { (byte)Envelope.DIME_VERSION, (byte)0x80, (byte)0x01, (byte)0x00, (byte)0x00, (byte)0x00 }; // version 1, EdDSA, Ed25519, public, extension, extension
            byte[] eddsaHeaderPublic = new byte[] { (byte)Envelope.DIME_VERSION, (byte)0x80, (byte)0x01, (byte)0x01, (byte)0x00, (byte)0x00 }; // version 1, EdDSA, Ed25519, private, extension, extension
            Key eddsa = Key.Generate(KeyType.Identity);
            byte[] bytesSecret = Base58.Decode(eddsa.Secret);
            byte[] bytesPublic = Base58.Decode(eddsa.Public);
            Assert.IsNotNull(bytesSecret);
            Assert.IsNotNull(bytesPublic);
            byte[] headerSecret = Utility.SubArray(bytesSecret, 0, 6);
            byte[] headerPublic = Utility.SubArray(bytesPublic, 0, 6);
            Assert.IsTrue(eddsaHeaderSecret.SequenceEqual(headerSecret));
            Assert.IsTrue(eddsaHeaderPublic.SequenceEqual(headerPublic));
        }

        [TestMethod]
        public void KeyHeaderTest4() {
            byte[] hashHeader = new byte[] { (byte)Envelope.DIME_VERSION, (byte)0xE0, (byte)0x01, (byte)0x02, (byte)0x00, (byte)0x00 }; // version 1, Secure Hashing, Blake2b, 256-bit, extension, extension
            Key hash = Key.Generate(KeyType.Authentication);
            Assert.IsNull(hash.Public);
            byte[] bytes = Base58.Decode(hash.Secret);
            Assert.IsNotNull(bytes);
            byte[] header = Utility.SubArray(bytes, 0, 6);
            Assert.IsTrue(hashHeader.SequenceEqual(header));
        }

        [TestMethod]
        public void contextTest1() {
            string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Key key = Key.Generate(KeyType.Identity, context);
            Assert.AreEqual(context, key.Context);
        }

        [TestMethod]
        public void contextTest2() {
            string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
            Key key1 = Key.Generate(KeyType.Identity, context);
            String exported = key1.Export();
            Key key2 = Item.Import<Key>(exported);
            Assert.AreEqual(context, key2.Context);
        }

        [TestMethod]
        public void contextTest3() {
            string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
            try {
                Key.Generate(KeyType.Identity, context);
            } catch (ArgumentException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

    }
}