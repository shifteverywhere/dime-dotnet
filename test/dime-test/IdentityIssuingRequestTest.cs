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
            try 
            {
                IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.GenerateKey(KeyType.Exchange));
            } 
            catch (Exception e) 
            {
                if (e is ArgumentException) { return; }
                throw e;
            } 
            Assert.IsTrue(false, $"Expected ArgumentException not thrown");
        }

        [TestMethod]
        public void GenerateRequestTest3()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.GenerateKey(KeyType.Identity));
        }

        [TestMethod]
        public void VerifyTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.GenerateKey(KeyType.Identity));
            iir.Verify();
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.GenerateKey(KeyType.Identity));
            string thumbprint = iir.Thumbprint();
            Assert.IsNotNull(thumbprint);
            Assert.IsTrue(thumbprint.Length > 0, "Thumbprint should not be empty string");
            Assert.IsTrue(thumbprint == iir.Thumbprint(), "Diffrent thumbprints produced from same claim");
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.Generate(KeyBox.GenerateKey(KeyType.Identity));
            IdentityIssuingRequest iir2 = IdentityIssuingRequest.Generate(KeyBox.GenerateKey(KeyType.Identity));
            Assert.IsFalse(iir1.Thumbprint() == iir2.Thumbprint(), "Thumbprints of diffrent iirs should not be the same");
        }

        [TestMethod]
        public void ExportTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(KeyBox.GenerateKey(KeyType.Identity));
            string encoded = iir.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("i1"));
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded = "i1.eyJpYXQiOjE2MjI0MTM4NzYsImlreSI6Ik1Db3dCUVlESzJWd0F5RUFkc3lUOW5UWjVBQnRDSWJRVmwxcVNyU1hCSzZVZkJGR3RvS0Ziay9ETS9NIiwiY2FwIjpbImdlbmVyaWMiXX0.ZCvziBYpFatLEfNCGAVpdR+DqHB1IhgrFpwHgYUn26QAm+Yw13AgPpBrhTDA9pmLgkFqTfXPab1TX0k7dmQHBg";
            IdentityIssuingRequest iir = Dime.Import<IdentityIssuingRequest>(encoded);
            Assert.IsNotNull(iir);
            Assert.AreEqual(ProfileVersion.One, iir.Profile);
            Assert.AreEqual(1622413876, iir.IssuedAt);
            Assert.IsTrue(iir.WantsCapability(Capability.Generic));
            Assert.AreEqual("MCowBQYDK2VwAyEAdsyT9nTZ5ABtCIbQVl1qSrSXBK6UfBFGtoKFbk/DM/M", iir.IdentityKey);
        }

    }

}