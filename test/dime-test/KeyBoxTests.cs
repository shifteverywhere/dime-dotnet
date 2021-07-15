//
//  KeyBoxTests.cs
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
    public class KeyBoxTests
    {
        [TestMethod]
        public void KeyBoxTest1()
        {
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            Assert.IsTrue(keypair.Profile == Profile.Uno);
            Assert.IsTrue(keypair.Type == KeyType.Identity);
            Assert.IsNotNull(keypair.UID);
            Assert.IsNotNull(keypair.PublicKey);
            Assert.IsNotNull(keypair.Key);
        }

        [TestMethod]
        public void KeyBoxTest2()
        {
            KeyBox keybox = KeyBox.Generate(KeyType.Exchange);
            Assert.IsTrue(keybox.Profile == Profile.Uno);
            Assert.IsTrue(keybox.Type == KeyType.Exchange);
            Assert.IsNotNull(keybox.UID);
            Assert.IsNotNull(keybox.PublicKey);
            Assert.IsNotNull(keybox.Key);
        }

        [TestMethod]
        public void ExportTest1()
        {
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            string encoded = keypair.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.StartsWith($"{Envelope.HEADER}:{KeyBox.TAG}"));
            Assert.IsTrue(encoded.Split(".").Length == 2);
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded = "Di:KEY.eyJraWQiOiI3MTc1NzFhMC0wNmY0LTQzZDUtYWUwMi00ZDMzMjQwMDExNDYiLCJpYXQiOjE2MjYzNzg0OTYsImtleSI6IkNZSGpYOWtOZUttdU1tb3Jwb1JhcDVCQUpjTDNOZTZEelZXaU56cjJBVHh4NlF5Y2pvZ3duVyIsInB1YiI6IkNZSHQ3Z1lXanpOeDV1enljZk4xOFlSMVIyTFBFZjU1aEFrdU5BQndLd0F4QU5BYmtaczlkdyJ9";
            KeyBox keybox = Item.Import<KeyBox>(encoded);
            Assert.AreEqual(Profile.Uno, keybox.Profile);
            Assert.AreEqual(KeyType.Identity, keybox.Type);
            Assert.AreEqual(new Guid("717571a0-06f4-43d5-ae02-4d3324001146"), keybox.UID);
            Assert.AreEqual(1626378496, keybox.IssuedAt);
            Assert.AreEqual("CYHjX9kNeKmuMmorpoRap5BAJcL3Ne6DzVWiNzr2ATxx6QycjogwnW", keybox.Key);
            Assert.AreEqual("CYHt7gYWjzNx5uzycfN18YR1R2LPEf55hAkuNABwKwAxANAbkZs9dw", keybox.PublicKey);
        }

        [TestMethod]
        public void KeypairTest3()
        {
            try {
                KeyBox keypair = KeyBox.Generate(KeyType.Identity, Profile.Undefined);
            } catch (UnsupportedProfileException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void PublicOnlyTest1()
        {
            KeyBox keybox = KeyBox.Generate(KeyType.Identity, Profile.Uno);
            Assert.IsNotNull(keybox.Key);
            KeyBox pubOnly = keybox.PublicOnly();
            Assert.IsNull(pubOnly.Key);
            Assert.AreEqual(keybox.UID, pubOnly.UID);
        }

        [TestMethod]
        public void PublicOnlyTest2()
        {
            KeyBox keybox = KeyBox.Generate(KeyType.Identity, Profile.Uno);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.SenderKeybox);
            KeyBox pubOnly = Commons.SenderKeybox.PublicOnly();
            message.Verify(pubOnly);            
        }

    }
}