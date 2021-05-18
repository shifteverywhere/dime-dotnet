using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class IdentityTests
    {
        [TestMethod]
        public void IdentityTest1()
        {
            int profile = 1;
            Guid subjectId = Guid.NewGuid();
            string identityKey = Keypair.GenerateKeypair(KeypairType.IdentityKey).publicKey;
            long issuedAt = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long expiresAt = issuedAt + 120;
            Guid issuerId = Guid.NewGuid();
            Identity identity = new Identity(subjectId, identityKey, issuedAt, expiresAt, issuerId, null, profile);
            Assert.IsTrue(profile == identity.profile);
            Assert.IsTrue(subjectId == identity.subjectId);
            Assert.IsTrue(identityKey == identity.identityKey);
            Assert.IsTrue(issuedAt == identity.issuedAt);
            Assert.IsTrue(expiresAt == identity.expiresAt);
            Assert.IsTrue(issuerId == identity.issuerId);
        }

        [TestMethod]
        public void IssueIdentityTest1()
        {
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            Identity identity = Identity.IssueIdentity(IdentityIssuingRequest.GenerateRequest(keypair), Guid.NewGuid(), keypair);
        }

        [TestMethod]
        public void IssueIdentityTest2()
        {
            IdentityTests.SetTrustedIdentity();
            IdentityIssuingRequest iir = IdentityIssuingRequest.GenerateRequest(Keypair.GenerateKeypair(KeypairType.IdentityKey));
            Identity identity = Identity.IssueIdentity(iir, Guid.NewGuid(), IdentityTests.rootKeypair);
        }

        [TestMethod]
        public void IssueIdentityTest3()
        {
            try
            {
                IdentityTests.SetTrustedIdentity();
                Keypair keypair1 = Keypair.GenerateKeypair(KeypairType.IdentityKey);
                Keypair keypair2 = Keypair.GenerateKeypair(KeypairType.IdentityKey);
                IdentityIssuingRequest iir = IdentityIssuingRequest.GenerateRequest( new Keypair(KeypairType.IdentityKey, keypair1.publicKey, keypair2.privateKey), 1);
                Identity identity = Identity.IssueIdentity(iir, Guid.NewGuid(), IdentityTests.rootKeypair);
            }
            catch (Exception e)
            {
                if (e is ArgumentException) { return; }
                throw e;
            }
            Assert.IsTrue(false, $"Expected ArgumentException not thrown");
        }        
    
        [TestMethod]
        public void IsSelfSignedTest1()
        {
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            Identity identity = Identity.IssueIdentity(IdentityIssuingRequest.GenerateRequest(keypair), Guid.NewGuid(), keypair);
            Assert.IsTrue(identity.IsSelfSigned());
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            IdentityTests.SetTrustedIdentity();
            IdentityIssuingRequest iir = IdentityIssuingRequest.GenerateRequest(Keypair.GenerateKeypair(KeypairType.IdentityKey));
            Identity identity = Identity.IssueIdentity(iir, Guid.NewGuid(), IdentityTests.rootKeypair);
            Assert.IsFalse(identity.IsSelfSigned());
        }

        [TestMethod]
        public void VerifyTrustTest1()
        {
            try 
            {
                Identity.trustedIdentity = null;
                Keypair keypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
                Identity identity = Identity.IssueIdentity(IdentityIssuingRequest.GenerateRequest(keypair), Guid.NewGuid(), keypair);
                identity.VerifyTrust();
            } 
            catch (Exception e) 
            {
                if (e is ArgumentException) { return; }
                throw e;
            } 
            Assert.IsTrue(false, $"Expected ArgumentException not thrown");
        }

        [TestMethod]
        public void VerifyTrustTest2()
        {
            IdentityTests.SetTrustedIdentity();
            Identity identity = Identity.IssueIdentity(IdentityIssuingRequest.GenerateRequest(Keypair.GenerateKeypair(KeypairType.IdentityKey)), Guid.NewGuid(), IdentityTests.rootKeypair);
            Assert.IsTrue(identity.VerifyTrust());
        }

        [TestMethod]
        public void VerifyTrustTest3()
        {
            IdentityTests.SetTrustedIdentity();
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            Identity identity = Identity.IssueIdentity(IdentityIssuingRequest.GenerateRequest(keypair), Guid.NewGuid(), keypair);
            Assert.IsFalse(identity.VerifyTrust());
        }

        [TestMethod]
        public void ExportTest1()
        {
            Keypair keypair = Crypto.GenerateKeyPair(1, KeypairType.IdentityKey);
            Identity identity = Identity.IssueIdentity(IdentityIssuingRequest.GenerateRequest(keypair), Guid.NewGuid(), keypair);
            string encoded = identity.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("I" + identity.profile.ToString()));
            Assert.IsTrue(encoded.Split(".").Length == 3);
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded = "I1.eyJzdWIiOiI2ZGU4NGQ4ZS1iNDlkLTRjOTEtYTc2YS01ZmVjMGY5ZmQ3MTgiLCJpYXQiOjE2MjEzNjUzMDEsImV4cCI6MTY1MjkwMTMwMSwiaXNzIjoiNmRlODRkOGUtYjQ5ZC00YzkxLWE3NmEtNWZlYzBmOWZkNzE4IiwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQWhmY0MwRXd1MWNhZ3RqQzMydS9mTy9xa1docW9IQzVkanNlZWk3MHc5TlEifQ.HxwzkWtoGFWdhGNr6S//Hnvn/IAi3cXc7NDiMzlF8DezcfPqUARs16Jjni7Is1fmthYLMOcH72gfdFP1QcdTCA";
            Identity identity = Identity.Import(encoded);
            Assert.IsNotNull(identity);
            Assert.AreEqual(identity.profile, 1);
            Assert.AreEqual(identity.subjectId, new Guid("6de84d8e-b49d-4c91-a76a-5fec0f9fd718"));
            Assert.AreEqual(identity.issuedAt, 1621365301);
            Assert.AreEqual(identity.expiresAt, 1652901301);
            Assert.AreEqual(identity.issuerId, new Guid("6de84d8e-b49d-4c91-a76a-5fec0f9fd718"));
            Assert.AreEqual(identity.identityKey, "MCowBQYDK2VwAyEAhfcC0Ewu1cagtjC32u/fO/qkWhqoHC5djseei70w9NQ");
            Assert.AreEqual(identity.signature, "HxwzkWtoGFWdhGNr6S//Hnvn/IAi3cXc7NDiMzlF8DezcfPqUARs16Jjni7Is1fmthYLMOcH72gfdFP1QcdTCA");
        }

        private static void SetTrustedIdentity()
        {
            IdentityTests.rootKeypair = Keypair.GenerateKeypair(KeypairType.IdentityKey);
            IdentityIssuingRequest irr = IdentityIssuingRequest.GenerateRequest(IdentityTests.rootKeypair);
            Identity.trustedIdentity = Identity.IssueIdentity(irr, Guid.NewGuid(), IdentityTests.rootKeypair);
        }

        private static Keypair rootKeypair;

    }

}
