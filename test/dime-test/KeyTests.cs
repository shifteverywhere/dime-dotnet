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
            Assert.IsTrue(key.Profile == Profile.Uno);
            Assert.IsTrue(key.Type == KeyType.Identity);
            Assert.IsNotNull(key.UniqueId);
            Assert.IsNotNull(key.Public);
            Assert.IsNotNull(key.Secret);
        }

        [TestMethod]
        public void KeyTest2()
        {
            Key key = Key.Generate(KeyType.Exchange);
            Assert.IsTrue(key.Profile == Profile.Uno);
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
            string encoded = "Di:KEY.eyJ1aWQiOiI0ZjQwMmI1NC1lY2FmLTRhNDctOTI3NC00YmUyNGFjNWJjZjQiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjQ3OjQ3LjAxMzIwNVoiLCJrZXkiOiJDWUhqWWJXWXdGWEhzamlLVTNIY25wSnZGc3pNQmZ4dHkxUXY5WGVCUG9zc1laWXhmR2p0aFAiLCJwdWIiOiJDWUh0NzV4S3pmWVl1ZTQ5TFVrcnU5SlRRQ3V6cUprMVRRd0xGODZBSmJpV0RBczZoVXcyTVMifQ";
            Key key = Item.Import<Key>(encoded);
            Assert.AreEqual(Profile.Uno, key.Profile);
            Assert.AreEqual(KeyType.Identity, key.Type);
            Assert.AreEqual(new Guid("4f402b54-ecaf-4a47-9274-4be24ac5bcf4"), key.UniqueId);
            Assert.AreEqual(DateTime.Parse("2021-08-09T10:47:47.013205Z"), key.IssuedAt);
            Assert.AreEqual("CYHjYbWYwFXHsjiKU3HcnpJvFszMBfxty1Qv9XeBPossYZYxfGjthP", key.Secret);
            Assert.AreEqual("CYHt75xKzfYYue49LUkru9JTQCuzqJk1TQwLF86AJbiWDAs6hUw2MS", key.Public);
        }

        [TestMethod]
        public void KeypairTest3()
        {
            try {
                Key key = Key.Generate(KeyType.Identity, -1, Profile.Undefined);
            } catch (UnsupportedProfileException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void PublicOnlyTest1()
        {
            Key key = Key.Generate(KeyType.Identity, -1, Profile.Uno);
            Assert.IsNotNull(key.Secret);
            Key pubOnly = key.PublicCopy();
            Assert.IsNull(pubOnly.Secret);
            Assert.AreEqual(key.UniqueId, pubOnly.UniqueId);
        }

        [TestMethod]
        public void PublicOnlyTest2()
        {
            Key key = Key.Generate(KeyType.Identity, -1, Profile.Uno);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            Key pubOnly = Commons.IssuerKey.PublicCopy();
            message.Verify(pubOnly);            
        }

    }
}