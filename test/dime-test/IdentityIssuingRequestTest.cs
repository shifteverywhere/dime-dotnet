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
        public void ExportTest1()
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
        public void ImportTest2()
        {
            string exported = "aW8uZGltZWZvcm1hdC5paXI.eyJpc3MiOm51bGwsInVpZCI6IjJhODIxM2Q2LThhYzItNDBjNS1iMzczLTA5NTYzZWEzZjZkZCIsImlhdCI6MTYyNTg1OTUwNSwicHViIjoiQ1lIdDc3MlNFUzQ0Zm1weVc5MkJjMWtyZnBiZXFQRG5STDY3Rkh5NjVXRXI5TnRCQ3pQY2l1IiwiY2FwIjpbImdlbmVyaWMiXX0.TDKgNeoBGp0pmjs3jcbjdfyPxA5Po3OfZf6fiNtibPOOHWw1qTAAsiO4uU+pP6x43Js1jZc9zP8hyU/lhaovAA";
            IdentityIssuingRequest iir = IdentityIssuingRequest.FromString(exported);
            Assert.IsNotNull(iir);
            Assert.AreEqual(new Guid("2a8213d6-8ac2-40c5-b373-09563ea3f6dd"), iir.UID);
            Assert.AreEqual(1625859505, iir.IssuedAt);
            Assert.IsTrue(iir.WantsCapability(Capability.Generic));
            Assert.AreEqual("CYHt772SES44fmpyW92Bc1krfpbeqPDnRL67FHy65WEr9NtBCzPciu", iir.PublicKey);
            iir.Verify();
        }

    }

}
