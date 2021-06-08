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
        public void GenerateRequestTest2()
        {
            try {
                IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Exchange));
            } catch (ArgumentException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void GenerateRequestTest3()
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
        public void ExportTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity));
            string encoded = iir.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 4);
            Assert.IsTrue(encoded.StartsWith(Dime.DIME_HEADER));
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded = "DI1.aW8uZGltZWZvcm1hdC5paXI.eyJpYXQiOjE2MjMxNzY4MDYsImlreSI6Ik1Db3dCUVlESzJWd0F5RUFPVTZBekptZkx5Y2tFaHZnTC9JYmtXZTJITkxJNWNaRmNIWHhjY2FuXHUwMDJCOU0iLCJjYXAiOlsiZ2VuZXJpYyJdfQ.nx1TFhbx7vhfu9c+RS6LJVpHy/eIKEKt1bx5rTU6pg7n+t+IIbWSdl3gT/B044jxhgl9uo1j7k+SCqxf0V2cAA";
            IdentityIssuingRequest iir = Dime.Import<IdentityIssuingRequest>(encoded);
            Assert.IsNotNull(iir);
            Assert.AreEqual(ProfileVersion.One, iir.Profile);
            Assert.AreEqual(1623176806, iir.IssuedAt);
            Assert.IsTrue(iir.WantsCapability(Capability.Generic));
            Assert.AreEqual("MCowBQYDK2VwAyEAOU6AzJmfLyckEhvgL/IbkWe2HNLI5cZFcHXxccan\u002B9M", iir.IdentityKey);
            iir.Verify();
        }

    }

}