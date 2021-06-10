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
            string exported = iir.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.Split(new char[] { '.' }).Length == 3);
            Assert.IsTrue(exported.StartsWith(Dime.HEADER));
        }

        [TestMethod]
        public void ImportTest2()
        {
            string exported = "DiME:aW8uZGltZWZvcm1hdC5paXI.eyJ2ZXIiOjEsInVpZCI6IjU3NDYyMWQ2LTdkY2UtNDE2Yi05ZDE0LWVkNWFiMjNiMTUzMSIsImlhdCI6MTYyMzM0MjE4NSwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQUpjU1NPenFYVm5Edms0RkNKXHUwMDJCVEpXdlpCWTcwMG5BWVNQZm4vUW9MczJSayIsImNhcCI6WyJnZW5lcmljIl19.YepImfzz4YPvvzzaay8bLCrkjz4ZpeY6lBhfBoF0RawbMbxcnk3Xo2QjfAOQoY6ISvNRX2EtXAdsABMXaeNHAQ";
            IdentityIssuingRequest iir = Dime.Import<IdentityIssuingRequest>(exported);
            Assert.IsNotNull(iir);
            Assert.AreEqual(ProfileVersion.One, iir.Profile);
            Assert.AreEqual(new Guid("574621d6-7dce-416b-9d14-ed5ab23b1531"), iir.Id);
            Assert.AreEqual(1623342185, iir.IssuedAt);
            Assert.IsTrue(iir.WantsCapability(Capability.Generic));
            Assert.AreEqual("MCowBQYDK2VwAyEAJcSSOzqXVnDvk4FCJ\u002BTJWvZBY700nAYSPfn/QoLs2Rk", iir.IdentityKey);
            iir.Verify();
        }
    }

}
