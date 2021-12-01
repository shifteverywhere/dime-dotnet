//
//  IdentityIssuingRequestTests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
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
            Assert.IsTrue(thumbprint == iir.Thumbprint(), "Different thumbprints produced from same claim");
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity));
            IdentityIssuingRequest iir2 = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity));
            Assert.IsFalse(iir1.Thumbprint() == iir2.Thumbprint(), "Thumbprints of different iirs should not be the same");
        }

        [TestMethod]
        public void ExportTest1()
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
        public void ImportTest1()
        {
            string exported = "Di:IIR.eyJ1aWQiOiJkNWRkNzEyZC1hM2U3LTQ3YjAtYjRmNi0yMjU2NzJlYzZkMjMiLCJpYXQiOiIyMDIxLTEyLTAxVDIxOjA4OjQ0LjQxMzMyNloiLCJwdWIiOiIyVERYZG9Odk0xVmhNWjhpRzVZNFVlZkVBQzVFQWZiR1NacGt6OUVoWkVGNEw1a1p5RzhuVDRTSkoiLCJjYXAiOlsiZ2VuZXJpYyJdfQ.eduHuVrUY/Q9xpZVApuPjBnbG4Oo29PeTPSQIRW6xJVRYZiH0h5jEL1MgZrIFxQRPyiBQlK6BMVTc6e7OwFVDw";
            IdentityIssuingRequest iir = Item.Import<IdentityIssuingRequest>(exported);
            Assert.IsNotNull(iir);
            Assert.AreEqual(new Guid("d5dd712d-a3e7-47b0-b4f6-225672ec6d23"), iir.UniqueId);
            Assert.AreEqual(DateTime.Parse("2021-12-01T21:08:44.413326Z").ToUniversalTime(), iir.IssuedAt);
            Assert.IsTrue(iir.WantsCapability(Capability.Generic));
            Assert.AreEqual("2TDXdoNvM1VhMZ8iG5Y4UefEAC5EAfbGSZpkz9EhZEF4L5kZyG8nT4SJJ", iir.PublicKey);
            iir.Verify();
        }

        [TestMethod]
        public void CapabilityTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> requestedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), requestedCapabilities);
            try
            {
                Identity identity = iir.Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, null);
            } catch (ArgumentException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }


        [TestMethod]
        public void CapabilityTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> requestedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify, Capability.Issue };
            List<Capability> allowedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), requestedCapabilities);
            try
            {
                Identity identity = iir.Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, allowedCapabilities);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void CapabilityTest3()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> requestedCapabilities = new List<Capability> { Capability.Generic };
            List<Capability> allowedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify };
            List<Capability> requiredCapabilities = new List<Capability> { Capability.Identify };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), requestedCapabilities);
            try
            {
                Identity identity = iir.Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, allowedCapabilities, requiredCapabilities);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void CapabilityTest4()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> requestedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify };
            List<Capability> allowedCapabilities = new List<Capability> { Capability.Generic, Capability.Identify };
            List<Capability> requiredCapabilities = new List<Capability> { Capability.Identify };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), requestedCapabilities);
            Identity identity = iir.Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, allowedCapabilities, requiredCapabilities);
            Assert.IsTrue(identity.HasCapability(requestedCapabilities[0]));
            Assert.IsTrue(identity.HasCapability(requestedCapabilities[1]));
        }
   
    }

}
