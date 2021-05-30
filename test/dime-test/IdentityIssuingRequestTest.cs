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
                IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Keypair.Generate(KeypairType.Exchange));
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
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Keypair.Generate(KeypairType.Identity));
        }

        [TestMethod]
        public void VerifyTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Keypair.Generate(KeypairType.Identity));
            iir.Verify();
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Keypair.Generate(KeypairType.Identity));
            string thumbprint = iir.Thumbprint();
            Assert.IsNotNull(thumbprint);
            Assert.IsTrue(thumbprint.Length > 0, "Thumbprint should not be empty string");
            Assert.IsTrue(thumbprint == iir.Thumbprint(), "Diffrent thumbprints produced from same claim");
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            IdentityIssuingRequest iir1 = IdentityIssuingRequest.Generate(Keypair.Generate(KeypairType.Identity));
            IdentityIssuingRequest iir2 = IdentityIssuingRequest.Generate(Keypair.Generate(KeypairType.Identity));
            Assert.IsFalse(iir1.Thumbprint() == iir2.Thumbprint(), "Thumbprints of diffrent iirs should not be the same");
        }

        [TestMethod]
        public void ExportTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Keypair.Generate(KeypairType.Identity));
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
            Assert.AreEqual(iir.Profile, 1);
            Assert.AreEqual(iir.IssuedAt, 1622413876);
            Assert.IsTrue(iir.HasCapability(Capability.Generic));
            Assert.AreEqual(iir.IdentityKey, "MCowBQYDK2VwAyEAdsyT9nTZ5ABtCIbQVl1qSrSXBK6UfBFGtoKFbk/DM/M");
        }

    }

}