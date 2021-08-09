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
            string encoded = "Di:KEY.eyJraWQiOiIxNGVkNzdmZC1lY2QwLTRiMTItYTdkYi00NTUwMGI0NjE2NGIiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjE4OjUzLjQ0OTQ1MVoiLCJrZXkiOiJDWUhqWU5HN2N1bzJEb1Nrd3ZiNm45QmlETlZ4RmVKcXdUaU5RMXQ3QnFLZEhNS1lmeVRtS20iLCJwdWIiOiJDWUh0N1prbnFZVExZdWJIdWFwNzJOOHN3cTZHZThKeFU1WjFWMUVGOUNqSEhmU05jQUU5RTcifQ";
            Key key = Item.Import<Key>(encoded);
            Assert.AreEqual(Profile.Uno, key.Profile);
            Assert.AreEqual(KeyType.Identity, key.Type);
            Assert.AreEqual(new Guid("14ed77fd-ecd0-4b12-a7db-45500b46164b"), key.UniqueId);
            Assert.AreEqual(DateTime.Parse("2021-08-09T10:18:53.449451Z"), key.IssuedAt);
            Assert.AreEqual("CYHjYNG7cuo2DoSkwvb6n9BiDNVxFeJqwTiNQ1t7BqKdHMKYfyTmKm", key.Secret);
            Assert.AreEqual("CYHt7ZknqYTLYubHuap72N8swq6Ge8JxU5Z1V1EF9CjHHfSNcAE9E7", key.Public);
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
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.SenderKey);
            Key pubOnly = Commons.SenderKey.PublicCopy();
            message.Verify(pubOnly);            
        }

    }
}