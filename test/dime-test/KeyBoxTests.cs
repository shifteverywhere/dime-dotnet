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
        public void ToStringTest1()
        {
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            string encoded = keypair.ToString();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.StartsWith(KeyBox.IID));
            Assert.IsTrue(encoded.Split(".").Length == 2);
        }

        [TestMethod]
        public void FromStringTest1()
        {
            string encoded = "a2V5.eyJraWQiOiJlZDM3ODJmNi1kY2ZmLTQ0MWQtYmY1MS1mZWRhZTZjMGEzZWMiLCJpYXQiOjE2MjYyMDgzODgsImtleSI6IkNZSGpYeHlEQXdnQ0hlMXFONjhSNUxrVVBNcXhQbUJ5M3Y5U0JMaTRqRlpiMnlSQ0N3bXlNZCIsInB1YiI6IkNZSHQ2dVRhOFp6QUNtNURhZ01OdHptQW1vYVF1VmFyTTF5dVhlVk02TDhyZGVRUFFtcmYxdyJ9";
            KeyBox keybox = KeyBox.FromString(encoded);
            Assert.AreEqual(Profile.Uno, keybox.Profile);
            Assert.AreEqual(KeyType.Identity, keybox.Type);
            Assert.AreEqual(new Guid("ed3782f6-dcff-441d-bf51-fedae6c0a3ec"), keybox.UID);
            Assert.AreEqual(1626208388, keybox.IssuedAt);
            Assert.AreEqual("CYHjXxyDAwgCHe1qN68R5LkUPMqxPmBy3v9SBLi4jFZb2yRCCwmyMd", keybox.Key);
            Assert.AreEqual("CYHt6uTa8ZzACm5DagMNtzmAmoaQuVarM1yuXeVM6L8rdeQPQmrf1w", keybox.PublicKey);
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
            message.Seal(Commons.SenderKeybox);
            KeyBox pubOnly = Commons.SenderKeybox.PublicOnly();
            message.Verify(pubOnly);            
        }

    }
}