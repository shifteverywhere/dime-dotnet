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
            string exported = "aWly.eyJpc3MiOm51bGwsInVpZCI6ImM1ZTUxNDA0LTkyODAtNDE5My04ZDYxLWEyY2RkOTFkZWZlNiIsImlhdCI6MTYyNjIwNzk3OSwicHViIjoiQ1lIdDhIVm1OSHF0ZXRTc054ZmNBQzc3VFZybkQ5b3FFTUZmbmFIRWViMmQxV0VtUml6V3JiIiwiY2FwIjpbImdlbmVyaWMiXX0.3O0XB9O4LFcOjKVntr+NpxDA7cqKWrviWTCmStEqPdc9Pui2MML1kgdYd9bU+62ulS/9OGVgwQ7S9JmRUCyfBQ";
            IdentityIssuingRequest iir = IdentityIssuingRequest.FromString(exported);
            Assert.IsNotNull(iir);
            Assert.AreEqual(new Guid("c5e51404-9280-4193-8d61-a2cdd91defe6"), iir.UID);
            Assert.AreEqual(1626207979, iir.IssuedAt);
            Assert.IsTrue(iir.WantsCapability(Capability.Generic));
            Assert.AreEqual("CYHt8HVmNHqtetSsNxfcAC77TVrnD9oqEMFfnaHEeb2d1WEmRizWrb", iir.PublicKey);
            iir.Verify();
        }

    }

}
