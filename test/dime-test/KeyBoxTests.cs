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
            Assert.IsTrue(keypair.Profile == ProfileVersion.One);
            Assert.IsTrue(keypair.Type == KeyType.Identity);
            Assert.IsNotNull(keypair.UID);
            Assert.IsNotNull(keypair.PublicKey);
            Assert.IsNotNull(keypair.Key);
        }

        [TestMethod]
        public void KeyBoxTest2()
        {
            KeyBox keybox = KeyBox.Generate(KeyType.Exchange);
            Assert.IsTrue(keybox.Profile == ProfileVersion.One);
            Assert.IsTrue(keybox.Type == KeyType.Exchange);
            Assert.IsNotNull(keybox.UID);
            Assert.IsNotNull(keybox.PublicKey);
            Assert.IsNotNull(keybox.Key);
        }

        [TestMethod]
        public void EncodedTest1()
        {
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            string encoded = keypair.ToString();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.StartsWith(KeyBox.IID));
            Assert.IsTrue(encoded.Split(".").Length == 2);
        }

        [TestMethod]
        public void DecodedTest1()
        {
            string encoded = "aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiIwZmYxYzMzMS0xYzNiLTQ1NjMtOTllMC04ZmUyMmJkODAyMDciLCJpYXQiOjE2MjU4NjI1MDQsImtleSI6IkNZSGpYOWsyWGREVUpHOGdaeGRnYTdMeExHTGdRZEtSQU50U0p0M1B5N2c4MW01dzM0M29EQiIsInB1YiI6IkNZSHQ3NG95eXZ4dld2dEZKdjNwaFZ3UVR3a042UzZwV2JUQm9Fb0hncWdjQjJrblJaa3ZERiJ9";
            KeyBox keybox = KeyBox.FromString(encoded);
            Assert.AreEqual(ProfileVersion.One, keybox.Profile);
            Assert.AreEqual(KeyType.Identity, keybox.Type);
            Assert.AreEqual(new Guid("0ff1c331-1c3b-4563-99e0-8fe22bd80207"), keybox.UID);
            Assert.AreEqual(1625862504, keybox.IssuedAt);
            Assert.AreEqual("CYHjX9k2XdDUJG8gZxdga7LxLGLgQdKRANtSJt3Py7g81m5w343oDB", keybox.Key);
            Assert.AreEqual("CYHt74oyyvxvWvtFJv3phVwQTwkN6S6pWbTBoEoHgqgcB2knRZkvDF", keybox.PublicKey);
        }

        [TestMethod]
        public void KeypairTest3()
        {
            try {
                KeyBox keypair = KeyBox.Generate(KeyType.Identity, ProfileVersion.Two);
            } catch (UnsupportedProfileException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void PublicOnlyTest1()
        {
            KeyBox keybox = KeyBox.Generate(KeyType.Identity, ProfileVersion.One);
            Assert.IsNotNull(keybox.Key);
            KeyBox pubOnly = keybox.PublicOnly();
            Assert.IsNull(pubOnly.Key);
            Assert.AreEqual(keybox.UID, pubOnly.UID);
        }

        [TestMethod]
        public void PublicOnlyTest2()
        {
            KeyBox keybox = KeyBox.Generate(KeyType.Identity, ProfileVersion.One);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeybox);
            KeyBox pubOnly = Commons.SenderKeybox.PublicOnly();
            message.Verify(pubOnly);            
        }

    }
}