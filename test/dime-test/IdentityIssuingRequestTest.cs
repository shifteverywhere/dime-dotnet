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
                IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Exchange));
            } catch (ArgumentException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void GenerateRequestTest2()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity));
        }

        [TestMethod]
        public void VerifyTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity));
            iir.Verify();
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity));
            string thumbprint = iir.Thumbprint();
            Assert.IsNotNull(thumbprint);
            Assert.IsTrue(thumbprint.Length > 0, "Thumbprint should not be empty string");
            Assert.IsTrue(thumbprint == iir.Thumbprint(), "Diffrent thumbprints produced from same claim");
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity));
            IdentityIssuingRequest iir2 = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity));
            Assert.IsFalse(iir1.Thumbprint() == iir2.Thumbprint(), "Thumbprints of diffrent iirs should not be the same");
        }

        [TestMethod]
        public void ToStringTest1()
        {
            Key key = Key.Generate(KeyType.Identity);
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(key);
            string exported = iir.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith($"{Envelope.HEADER}:{IdentityIssuingRequest.TAG}"));
            Assert.IsTrue(exported.Split(new char[] { '.' }).Length == 3);
        }

        [TestMethod]
        public void FromStringTest2()
        {
            string exported = "Di:IIR.eyJ1aWQiOiI1YmE5OGJlOS0zMmRmLTQxMmUtYWQ4ZC05OTgzOWM4MWMxMmUiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjE0OjI3Ljc3NjQzNloiLCJwdWIiOiJDWUh0NlhTRHBvdnZ2VnQxNDZtWW1XemE2Q29CbW5qdENSRW5ZVWl1VHBlZzdlaWROU2RmMzIiLCJjYXAiOlsiZ2VuZXJpYyJdfQ.ASZGxVADMvXI4elwkPxn0tAJe7yN32YUXIpxlJtO5T0etq8UchdWILXb7XWfHegc6q1uCR3GQf/u/aNpEDZ3FQU";
            IdentityIssuingRequest iir = Item.Import<IdentityIssuingRequest>(exported);
            Assert.IsNotNull(iir);
            Assert.AreEqual(new Guid("5ba98be9-32df-412e-ad8d-99839c81c12e"), iir.UniqueId);
            Assert.AreEqual(DateTime.Parse("2021-08-09T10:14:27.776436Z"), iir.IssuedAt);
            Assert.IsTrue(iir.WantsCapability(Capability.Generic));
            Assert.AreEqual("CYHt6XSDpovvvVt146mYmWza6CoBmnjtCREnYUiuTpeg7eidNSdf32", iir.PublicKey);
            iir.Verify();
        }
        
    }

}
