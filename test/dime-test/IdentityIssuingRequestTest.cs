//
//  IdentityIssuingRequestTests.cs
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
    public class IdentityIssuingRequestTests
    {  
        [TestMethod]
        public void GenerateRequestTest1()
        {
            try {
                IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Exchange));
            } catch (ArgumentException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void GenerateRequestTest2()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity));
        }

        [TestMethod]
        public void VerifyTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity));
            iir.Verify();
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity));
            string thumbprint = iir.Thumbprint();
            Assert.IsNotNull(thumbprint);
            Assert.IsTrue(thumbprint.Length > 0, "Thumbprint should not be empty string");
            Assert.IsTrue(thumbprint == iir.Thumbprint(), "Diffrent thumbprints produced from same claim");
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity));
            IdentityIssuingRequest iir2 = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity));
            Assert.IsFalse(iir1.Thumbprint() == iir2.Thumbprint(), "Thumbprints of diffrent iirs should not be the same");
        }

        [TestMethod]
        public void ToStringTest1()
        {
            KeyBox keybox = KeyBox.Generate(KeyType.Identity);
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(keybox);
            string exported = iir.ToString();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(IdentityIssuingRequest.IID));
            Assert.IsTrue(exported.Split(new char[] { '.' }).Length == 3);
        }

        [TestMethod]
        public void FromStringTest2()
        {
            string exported = "aWly.eyJ1aWQiOiIxYTEyNDU0Yi1hNjIzLTRmNjEtYWRlMi03ZWViZDQ1MzJhYzkiLCJpYXQiOjE2MjYyMTMxMDgsInB1YiI6IkNZSHQ2YXJ4clNOemR4b1Y3cVFkQ2U4VHFCY2dIV0xkU2V6NXRLTEhaREpjazY1azhSUDdBcSIsImNhcCI6WyJnZW5lcmljIl19.Adl3udTSoJhqpNw7K5OVmBuad8sl6zZBJguxJ15WdKuFf5BhfXB1grrzPPiQZOcvcbt90beHKmeNZ0xjh7JksAM";
            IdentityIssuingRequest iir = IdentityIssuingRequest.FromString(exported);
            Assert.IsNotNull(iir);
            Assert.AreEqual(new Guid("1a12454b-a623-4f61-ade2-7eebd4532ac9"), iir.UID);
            Assert.AreEqual(1626213108, iir.IssuedAt);
            Assert.IsTrue(iir.WantsCapability(Capability.Generic));
            Assert.AreEqual("CYHt6arxrSNzdxoV7qQdCe8TqBcgHWLdSez5tKLHZDJck65k8RP7Aq", iir.PublicKey);
            iir.Verify();
        }

    }

}
