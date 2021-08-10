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
            string encoded = "Di:KEY.eyJ1aWQiOiIzMTEyNjAxYS0xZWFlLTRkYjgtYTczYi0wNDc0N2EzOGU4N2MiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjM0OjQzLjUxNzIzWiIsImtleSI6IjFoRWl3UjNCcUxZMkV1QVJYZFpVRmFIb2l1aDVSdVg1dlZZNW4xNWVnVTVReFhuU2VYbUFjIiwicHViIjoiMWhQS3luTG1xaWlDa1RHN1JIendtOVFXTXJvaFdFMjV5bTgzQTdZbW9wQ2hIWWF2YUFEemcifQ";
            Key key = Item.Import<Key>(encoded);
            Assert.AreEqual(Profile.Uno, key.Profile);
            Assert.AreEqual(KeyType.Identity, key.Type);
            Assert.AreEqual(new Guid("3112601a-1eae-4db8-a73b-04747a38e87c"), key.UniqueId);
            Assert.AreEqual(DateTime.Parse("2021-08-10T06:34:43.51723Z"), key.IssuedAt);
            Assert.AreEqual("1hEiwR3BqLY2EuARXdZUFaHoiuh5RuX5vVY5n15egU5QxXnSeXmAc", key.Secret);
            Assert.AreEqual("1hPKynLmqiiCkTG7RHzwm9QWMrohWE25ym83A7YmopChHYavaADzg", key.Public);
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