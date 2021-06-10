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
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class KeyBoxTests
    {
        [TestMethod]
        public void KeypairTest1()
        {
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            Assert.IsTrue(keypair.Profile == ProfileVersion.One);
            Assert.IsTrue(keypair.Type == KeyType.Identity);
            Assert.IsNotNull(keypair.Id);
            Assert.IsNotNull(keypair.PublicKey);
            Assert.IsNotNull(keypair.Key);
        }

        [TestMethod]
        public void EncodedTest1()
        {
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            string encoded = keypair.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.StartsWith(Dime.HEADER));
            Assert.IsTrue(encoded.Split(".").Length == 2);
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded ="DiME:aW8uZGltZWZvcm1hdC5reWI.eyJ2ZXIiOjEsImtpZCI6IjEzZDNhNTAxLWM4ZjYtNGIyYS04YjM3LThiOWJlMDNkYTJiYiIsImt0eSI6MSwia2V5IjoiTUM0Q0FRQXdCUVlESzJWd0JDSUVJTjAxRVx1MDAyQllpTHBWdFBpQnRsdWtKQ2R3TmJKZXByZ1FhQm5XRkxLQ0V6OVBaIiwicHViIjoiTUNvd0JRWURLMlZ3QXlFQUVPOHdZa1cydWd0aGRNR014djBjajAwVi9IZ3BnOENHU2JMM3BGOXZLNlEifQ";
            KeyBox keypair = Dime.Import<KeyBox>(encoded);
            Assert.AreEqual(ProfileVersion.One, keypair.Profile);
            Assert.AreEqual(KeyType.Identity, keypair.Type);
            Assert.AreEqual(new Guid("13d3a501-c8f6-4b2a-8b37-8b9be03da2bb"), keypair.Id);
            Assert.AreEqual("MC4CAQAwBQYDK2VwBCIEIN01E\u002BYiLpVtPiBtlukJCdwNbJeprgQaBnWFLKCEz9PZ", keypair.Key);
            Assert.AreEqual("MCowBQYDK2VwAyEAEO8wYkW2ugthdMGMxv0cj00V/Hgpg8CGSbL3pF9vK6Q", keypair.PublicKey);
        }

        [TestMethod]
        public void KeypairTest3()
        {
            try {
                KeyBox keypair = KeyBox.Generate(KeyType.Identity, ProfileVersion.Two);
            } catch (UnsupportedProfileException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

    }
}