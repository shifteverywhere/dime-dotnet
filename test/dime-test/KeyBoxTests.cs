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
            KeyBox keypair = KeyBox.GenerateKey(KeyType.Identity);
            Assert.IsTrue(keypair.Profile == ProfileVersion.One);
            Assert.IsTrue(keypair.Type == KeyType.Identity);
            Assert.IsNotNull(keypair.Id);
            Assert.IsNotNull(keypair.PublicKey);
            Assert.IsNotNull(keypair.Key);
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded = "k1.eyJraWQiOiI4MThiNDBlMC03YzM2LTRlZTQtYTExMC0zMzMxNmFlOGI1MjkiLCJrdHkiOjEsImtleSI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSUY2T0pcdTAwMkJvOE5mcDF4NzRxZXhyRWIyYy96Z2p0eXdOM2FKUDhVblNhQi8vNCIsInB1YiI6Ik1Db3dCUVlESzJWd0F5RUE0dEU1eUlTYjNlZjFaNUxRWTBRWjdRZ0JmUkFcdTAwMkJyNkFJSEVtd1pYWDcwZkkifQ";
            KeyBox keypair = Dime.Import<KeyBox>(encoded);
            Assert.AreEqual(ProfileVersion.One, keypair.Profile);
            Assert.AreEqual(KeyType.Identity, keypair.Type);
            Assert.AreEqual(new Guid("818b40e0-7c36-4ee4-a110-33316ae8b529"), keypair.Id);
            Assert.AreEqual("MC4CAQAwBQYDK2VwBCIEIF6OJ\u002Bo8Nfp1x74qexrEb2c/zgjtywN3aJP8UnSaB//4", keypair.Key);
            Assert.AreEqual("MCowBQYDK2VwAyEA4tE5yISb3ef1Z5LQY0QZ7QgBfRA\u002Br6AIHEmwZXX70fI", keypair.PublicKey);
        }

        [TestMethod]
        public void KeypairTest3()
        {
            try {
                KeyBox keypair = KeyBox.GenerateKey(KeyType.Identity, 0);
            } catch (UnsupportedProfileException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

    }
}