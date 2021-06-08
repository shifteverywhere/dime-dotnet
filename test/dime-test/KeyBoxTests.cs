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
        public void ImportTest1()
        {
            string encoded = "DI1.aW8uZGltZWZvcm1hdC5reWI.eyJraWQiOiJkMzJjMWE4MC00MGM0LTQ2NjgtOGY5My0zYjU5OWQyMzNlMTMiLCJrdHkiOjEsImtleSI6Ik1DNENBUUF3QlFZREsyVndCQ0lFSU9NZWZRempmdVEwRFlhZjNad013UVEzZ3NYT05BNHBHU0ltSXhYaTZ5dkgiLCJwdWIiOiJNQ293QlFZREsyVndBeUVBRkdGNlYva1x1MDAyQk9vbTFcdTAwMkJhZlVPS2V5NjNMMGtzSnBpV3E4XHUwMDJCdFx1MDAyQnliZEJMMFgwIn0";
            KeyBox keypair = Dime.Import<KeyBox>(encoded);
            Assert.AreEqual(ProfileVersion.One, keypair.Profile);
            Assert.AreEqual(KeyType.Identity, keypair.Type);
            Assert.AreEqual(new Guid("d32c1a80-40c4-4668-8f93-3b599d233e13"), keypair.Id);
            Assert.AreEqual("MC4CAQAwBQYDK2VwBCIEIOMefQzjfuQ0DYaf3ZwMwQQ3gsXONA4pGSImIxXi6yvH", keypair.Key);
            Assert.AreEqual("MCowBQYDK2VwAyEAFGF6V/k\u002BOom1\u002BafUOKey63L0ksJpiWq8\u002Bt\u002BybdBL0X0", keypair.PublicKey);
        }

        [TestMethod]
        public void KeypairTest3()
        {
            try {
                KeyBox keypair = KeyBox.Generate(KeyType.Identity, 0);
            } catch (UnsupportedProfileException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

    }
}