//
//  KeyTests.cs
//  DiME - Digital Identity Message Envelope
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
            string encoded = "Di:KEY.eyJraWQiOiI3MTc1NzFhMC0wNmY0LTQzZDUtYWUwMi00ZDMzMjQwMDExNDYiLCJpYXQiOjE2MjYzNzg0OTYsImtleSI6IkNZSGpYOWtOZUttdU1tb3Jwb1JhcDVCQUpjTDNOZTZEelZXaU56cjJBVHh4NlF5Y2pvZ3duVyIsInB1YiI6IkNZSHQ3Z1lXanpOeDV1enljZk4xOFlSMVIyTFBFZjU1aEFrdU5BQndLd0F4QU5BYmtaczlkdyJ9";
            Key key = Item.Import<Key>(encoded);
            Assert.AreEqual(Profile.Uno, key.Profile);
            Assert.AreEqual(KeyType.Identity, key.Type);
            Assert.AreEqual(new Guid("717571a0-06f4-43d5-ae02-4d3324001146"), key.UniqueId);
            Assert.AreEqual(1626378496, key.IssuedAt);
            Assert.AreEqual("CYHjX9kNeKmuMmorpoRap5BAJcL3Ne6DzVWiNzr2ATxx6QycjogwnW", key.Secret);
            Assert.AreEqual("CYHt7gYWjzNx5uzycfN18YR1R2LPEf55hAkuNABwKwAxANAbkZs9dw", key.Public);
        }

        [TestMethod]
        public void KeypairTest3()
        {
            try {
                Key key = Key.Generate(KeyType.Identity, Profile.Undefined);
            } catch (UnsupportedProfileException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void PublicOnlyTest1()
        {
            Key key = Key.Generate(KeyType.Identity, Profile.Uno);
            Assert.IsNotNull(key.Secret);
            Key pubOnly = key.PublicOnly();
            Assert.IsNull(pubOnly.Secret);
            Assert.AreEqual(key.UniqueId, pubOnly.UniqueId);
        }

        [TestMethod]
        public void PublicOnlyTest2()
        {
            Key key = Key.Generate(KeyType.Identity, Profile.Uno);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.SenderKey);
            Key pubOnly = Commons.SenderKey.PublicOnly();
            message.Verify(pubOnly);            
        }

    }
}