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
            string encoded = "I1.eyJzdWIiOiI5OGFkZTRhYy02YzExLTQzYWYtYjQ3NS1hOGQ5MjMwN2JmOTQiLCJpc3MiOiI5OGFkZTRhYy02YzExLTQzYWYtYjQ3NS1hOGQ5MjMwN2JmOTQiLCJpYXQiOjE2MjE1Mzc1MjksImV4cCI6MTY1MzA3MzUyOSwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQXFYL014XHUwMDJCRkcxNUFEbnVPVGIwWENLVi9CMG5aSzFrN21GY3NJU2twczJWdyJ9.NBWnpkewhWgNUfs6SMAM9oFNvnYpn4rmFcW8DdeKe0gVMft4vfjMoJP9ydraE1aw1807GCK60Sk5svblpYP7DQ";
            Identity identity = Identity.Import(encoded);
            Assert.IsNotNull(identity);
            Assert.AreEqual(identity.profile, 1);
            Assert.AreEqual(new Guid("98ade4ac-6c11-43af-b475-a8d92307bf94"), identity.subjectId);
            Assert.AreEqual(1621537529, identity.issuedAt);
            Assert.AreEqual(1653073529, identity.expiresAt);
            Assert.AreEqual(new Guid("98ade4ac-6c11-43af-b475-a8d92307bf94"), identity.issuerId);
            Assert.AreEqual(identity.identityKey, "MCowBQYDK2VwAyEAqX/Mx\u002BFG15ADnuOTb0XCKV/B0nZK1k7mFcsISkps2Vw");
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
