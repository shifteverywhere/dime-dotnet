using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class IdentityTests
    {

        [TestMethod]
        public void IssueTest1()
        {
            Dime.SetTrustedIdentity(null);
            ProfileVersion profile = ProfileVersion.One;
            Guid subjectId = Guid.NewGuid();
            KeyBox keypair = KeyBox.GenerateKey(KeyType.Identity, profile);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, 100, caps,  keypair,  null);
            Assert.IsTrue(profile == identity.Profile);
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(subjectId == identity.IssuerId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(identity.HasCapability(caps[1]));
            Assert.IsTrue(identity.HasCapability(Capability.Self));
            Assert.IsTrue(keypair.PublicKey == identity.IdentityKey);
            Assert.IsTrue(identity.IssuedAt != 0);
            Assert.IsTrue(identity.IssuedAt < identity.ExpiresAt);
            Assert.IsTrue(subjectId == identity.IssuerId);
        }

        [TestMethod]
        public void IssueTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            ProfileVersion profile = ProfileVersion.One;
            Guid subjectId = Guid.NewGuid();
            KeyBox keypair = KeyBox.GenerateKey(KeyType.Identity, profile);
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(keypair, caps);
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, 100, caps, Commons.IntermediateKeypair, Commons.IntermediateIdentity);
            Assert.IsTrue(profile == identity.Profile);
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(keypair.PublicKey == identity.IdentityKey);
            Assert.IsTrue(identity.IssuedAt != 0);
            Assert.IsTrue(identity.IssuedAt < identity.ExpiresAt);
            Assert.IsTrue(Commons.IntermediateIdentity.SubjectId == identity.IssuerId);
        }

       [TestMethod]
        public void IssueTest3()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> reqCaps = new List<Capability> { Capability.Issue };
            List<Capability> allowCaps = new List<Capability> { Capability.Generic, Capability.Identify };
            try {
                Identity identity = IdentityIssuingRequest.Generate(KeyBox.GenerateKey(KeyType.Identity), reqCaps).IssueIdentity(Guid.NewGuid(), 100, allowCaps, Commons.TrustedKeypair, Commons.TrustedIdentity);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            KeyBox keypair = KeyBox.GenerateKey(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.TrustedKeypair, Commons.TrustedIdentity);
            Assert.IsTrue(identity.HasCapability(Capability.Issue));
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
        }

        [TestMethod]
        public void IsSelfSignedTest1()
        {
            Dime.SetTrustedIdentity(null);
            KeyBox keypair = KeyBox.GenerateKey(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
            Assert.IsTrue(identity.IsSelfSigned());
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(KeyBox.GenerateKey(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKeypair, Commons.IntermediateIdentity);
            Assert.IsFalse(identity.IsSelfSigned());
        }

        [TestMethod]
        public void VerifyTrustTest1()
        {
            try 
            {
                Dime.SetTrustedIdentity(null);
                List<Capability> caps = new List<Capability> { Capability.Generic };
                KeyBox keypair = KeyBox.GenerateKey(KeyType.Identity);
                Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
                Assert.IsTrue(identity.IsSelfSigned());
                identity.Verify();
            } 
            catch (Exception e) 
            {
                if (e is UntrustedIdentityException) { return; }
                throw e;
            } 
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void VerifyTrustTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(KeyBox.GenerateKey(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKeypair, Commons.IntermediateIdentity);
            identity.Verify();
        }

        [TestMethod]
        public void VerifyTrustTest3()
        {
            Dime.SetTrustedIdentity(null);
            Capability[] caps = new Capability[1] { Capability.Generic };
            KeyBox keypair = KeyBox.GenerateKey(KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            try {
                identity.Verify();
            } catch (UntrustedIdentityException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void VerifyTrustTest4()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Commons.IntermediateIdentity.Verify();
        }

        [TestMethod]
        public void ExportTest1()
        {
            Dime.SetTrustedIdentity(null);
            Capability[] caps = new Capability[1] { Capability.Generic };
            KeyBox keypair = Crypto.GenerateKeyPair(ProfileVersion.One, KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
            string encoded = identity.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("I" + (int)identity.Profile));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 3);
        }

        [TestMethod]
        public void ImportTest1()
        {
            Dime.SetTrustedIdentity(null);
            string encoded = "I1.eyJzdWIiOiI5M2YyOTZkZC00NGNjLTQ1NDEtYWIzNi1jMmUyZDVjMDZkMjIiLCJpc3MiOiI4NDM3MDNiMC03ODFjLTRlNTYtYjMwNi0wYTVlYjU3YzVmYzkiLCJpYXQiOjE2MjI0OTA4MzksImV4cCI6MTY1NDAyNjgzOSwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQTR0RTV5SVNiM2VmMVo1TFFZMFFaN1FnQmZSQVx1MDAyQnI2QUlIRW13WlhYNzBmSSIsImNhcCI6WyJnZW5lcmljIl19.STEuZXlKemRXSWlPaUk0TkRNM01ETmlNQzAzT0RGakxUUmxOVFl0WWpNd05pMHdZVFZsWWpVM1l6Vm1ZemtpTENKcGMzTWlPaUk0T0dGbVpqQmxNaTFrWVRNNExUUXlZV1F0T0dWa1pDMDJZemcyWkRnNVl6ZG1NamdpTENKcFlYUWlPakUyTWpJME9UQTNNakFzSW1WNGNDSTZNVGt6TnpnMU1EY3lNQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFVTlhiMjk0TW5wYVdYUmFTV0ZMTjBOQk9XMXRiMEZFWVdSQ2RVTjRaRU5TTTJsS1QweHZaazkxZFVraUxDSmpZWEFpT2xzaWFYTnpkV1VpTENKblpXNWxjbWxqSWwxOS5yTDg5dldoMW5oR3hVM2p2ZS9zTk1YbTNlZU9ORGRwbkVUdExPQm5MVkhGa2dZSU1JWkgxOGxNeWpMQzQ0WGxaRHRSSlVFOWhxNEU0ckRDQUJFamhBQQ.J0lRRe+NFmYPrpSPjL4TjNoyuC0rrWrXrB3hl6H4ae8Z3Lf3lWZ9aiqmL/f8L3iKZemlz+8lYJCy6KCfoLN8Ag";
            Identity identity = Dime.Import<Identity>(encoded);
            Assert.IsNotNull(identity);
            Assert.AreEqual(ProfileVersion.One, identity.Profile);
            Assert.AreEqual(new Guid("93f296dd-44cc-4541-ab36-c2e2d5c06d22"), identity.SubjectId);
            Assert.AreEqual(1622490839, identity.IssuedAt);
            Assert.AreEqual(1654026839, identity.ExpiresAt);
            Assert.AreEqual(new Guid("843703b0-781c-4e56-b306-0a5eb57c5fc9"), identity.IssuerId);
            Assert.AreEqual("MCowBQYDK2VwAyEA4tE5yISb3ef1Z5LQY0QZ7QgBfRA\u002Br6AIHEmwZXX70fI", identity.IdentityKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsNotNull(identity.TrustChain);
            Assert.AreEqual(new Guid("843703b0-781c-4e56-b306-0a5eb57c5fc9"), identity.TrustChain.SubjectId);
        }

    }

}
