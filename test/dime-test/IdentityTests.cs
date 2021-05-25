using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class IdentityTests
    {
        [TestMethod]
        public void Test1()
        {
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Identity.Capability[] caps = new Identity.Capability[1] { Identity.Capability.Issue };
            IdentityIssuingRequest iir = IdentityIssuingRequest.GenerateRequest(keypair, caps);
            Identity identity = Identity.Issue(iir, Guid.NewGuid(), caps, 100, keypair, null);

        }

        [TestMethod]
        public void IssueIdentityTest1()
        {
            int profile = 1;
            Guid subjectId = Guid.NewGuid();
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity, profile);
            Identity.Capability[] caps = new Identity.Capability[2] { Identity.Capability.Issue, Identity.Capability.Authorize };
            Identity identity = Identity.Issue(IdentityIssuingRequest.GenerateRequest(keypair, caps), subjectId, caps, 100, keypair, null);
            Assert.IsTrue(profile == identity.Profile);
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(subjectId == identity.IssuerId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(identity.HasCapability(caps[1]));
            Assert.IsTrue(keypair.PublicKey == identity.identityKey);
            Assert.IsTrue(identity.IssuedAt != 0);
            Assert.IsTrue(identity.IssuedAt < identity.ExpiresAt);
            Assert.IsTrue(subjectId == identity.IssuerId);
        }

        [TestMethod]
        public void IssueIdentityTest2()
        {
            IdentityTests.SetTrustedIdentity();
            int profile = 1;
            Guid subjectId = Guid.NewGuid();
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity, profile);
            Identity.Capability[] caps = new Identity.Capability[1] { Identity.Capability.Authorize };
            IdentityIssuingRequest iir = IdentityIssuingRequest.GenerateRequest(keypair);
            Identity identity = Identity.Issue(iir, subjectId, caps, 100, IdentityTests.rootKeypair, Identity.TrustedIdentity);
            Assert.IsTrue(profile == identity.Profile);
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(keypair.PublicKey == identity.identityKey);
            Assert.IsTrue(identity.IssuedAt != 0);
            Assert.IsTrue(identity.IssuedAt < identity.ExpiresAt);
            Assert.IsTrue(Identity.TrustedIdentity.SubjectId == identity.IssuerId);
        }

       [TestMethod]
        public void IssueIdentityTest3()
        {
            IdentityTests.SetTrustedIdentity();
            Identity.Capability[] caps = new Identity.Capability[1] { Identity.Capability.Issue };
            IdentityIssuingRequest iir = IdentityIssuingRequest.GenerateRequest(Keypair.GenerateKeypair(KeypairType.Identity));
            try {
                Identity identity = Identity.Issue(iir, Guid.NewGuid(), caps, 100, IdentityTests.rootKeypair, Identity.TrustedIdentity);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSelfSignedTest1()
        {
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Identity.Capability[] caps = new Identity.Capability[2] { Identity.Capability.Issue, Identity.Capability.Authorize };
            Identity identity = Identity.Issue(IdentityIssuingRequest.GenerateRequest(keypair, caps), Guid.NewGuid(), caps, 100, keypair, null);
            Assert.IsTrue(identity.IsSelfSigned());
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            IdentityTests.SetTrustedIdentity();
            Identity.Capability[] caps = new Identity.Capability[1] { Identity.Capability.Authorize };
            IdentityIssuingRequest iir = IdentityIssuingRequest.GenerateRequest(Keypair.GenerateKeypair(KeypairType.Identity));
            Identity identity = Identity.Issue(iir, Guid.NewGuid(), caps, 100, IdentityTests.rootKeypair, Identity.TrustedIdentity);
            Assert.IsFalse(identity.IsSelfSigned());
        }

        [TestMethod]
        public void VerifyTrustTest1()
        {
            try 
            {
                Identity.TrustedIdentity = null;
                Identity.Capability[] caps = new Identity.Capability[1] { Identity.Capability.Authorize };
                Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity);
                Identity identity = Identity.Issue(IdentityIssuingRequest.GenerateRequest(keypair), Guid.NewGuid(), caps, 100, keypair, null);
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
            Identity.Capability[] caps = new Identity.Capability[1] { Identity.Capability.Authorize };
            Identity identity = Identity.Issue(IdentityIssuingRequest.GenerateRequest(Keypair.GenerateKeypair(KeypairType.Identity)), Guid.NewGuid(), caps, IdentityTests.rootKeypair, 100, Identity.TrustedIdentity);
            identity.VerifyTrust();
        }

        [TestMethod]
        public void VerifyTrustTest3()
        {
            Identity.Capability[] caps = new Identity.Capability[1] { Identity.Capability.Authorize };
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Identity identity = Identity.Issue(IdentityIssuingRequest.GenerateRequest(keypair), Guid.NewGuid(), caps, keypair, 100, null);
            IdentityTests.SetTrustedIdentity();
            try {
                identity.VerifyTrust();
            } catch (UntrustedIdentityException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void ExportTest1()
        {
            Identity.Capability[] caps = new Identity.Capability[1] { Identity.Capability.Authorize };
            Keypair keypair = Crypto.GenerateKeyPair(1, KeypairType.Identity);
            Identity identity = Identity.Issue(IdentityIssuingRequest.GenerateRequest(keypair), Guid.NewGuid(), caps, keypair, 100, null);
            string encoded = identity.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("I" + identity.Profile.ToString()));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 3);
        }

        [TestMethod]
        public void ImportTest1()
        {
            string encoded = "I1.eyJzdWIiOiI0NjFiNTI5Yy1iNjk0LTQxODItOGU5My0xNjliMjg1MjRlNWEiLCJpc3MiOiI0NjFiNTI5Yy1iNjk0LTQxODItOGU5My0xNjliMjg1MjRlNWEiLCJpYXQiOjE2MjE4OTEwMDcsImV4cCI6MTY1MzQyNzAwNywiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQXVzR0FcdTAwMkI1aTU5a0k3SmlUTXY5VlJcdTAwMkJsNkkzNXIzbmw4VlphVmhGdWpKTWlRIiwiY2FwIjpbImF1dGhvcml6ZSJdfQ.NSQJoG/E2qke3/BCK9M9qGa+p+vB0qYuFbG149uyEhDJ9eKVrSoTEsVAY736SW0O+a1eY8cuxABWguvCq4OXBQ";
            Identity identity = Identity.Import(encoded);
            Assert.IsNotNull(identity);
            Assert.AreEqual(identity.Profile, 1);
            Assert.AreEqual(new Guid("461b529c-b694-4182-8e93-169b28524e5a"), identity.SubjectId);
            Assert.AreEqual(1621891007, identity.IssuedAt);
            Assert.AreEqual(1653427007, identity.ExpiresAt);
            Assert.AreEqual(new Guid("461b529c-b694-4182-8e93-169b28524e5a"), identity.IssuerId);
            Assert.AreEqual(identity.identityKey, "MCowBQYDK2VwAyEAusGA\u002B5i59kI7JiTMv9VR\u002Bl6I35r3nl8VZaVhFujJMiQ");
            Assert.IsTrue(identity.HasCapability(Identity.Capability.Authorize));
        }

        private static void SetTrustedIdentity()
        {
            Identity.Capability[] caps = new Identity.Capability[2] { Identity.Capability.Issue, Identity.Capability.Authorize };
            IdentityTests.rootKeypair = Keypair.GenerateKeypair(KeypairType.Identity);
            IdentityIssuingRequest irr = IdentityIssuingRequest.GenerateRequest(IdentityTests.rootKeypair, caps);
            Identity.TrustedIdentity = Identity.Issue(irr, Guid.NewGuid(), caps, IdentityTests.rootKeypair, 100, null);
        }

        private static Keypair rootKeypair;

    }

}
