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
            Identity.TrustedIdentity = null;
            int profile = 1;
            Guid subjectId = Guid.NewGuid();
            Keypair keypair = Keypair.Generate(KeypairType.Identity, profile);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = Identity.Issue(IdentityIssuingRequest.Generate(keypair, caps), subjectId, 100, keypair);
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            int profile = 1;
            Guid subjectId = Guid.NewGuid();
            Keypair keypair = Keypair.Generate(KeypairType.Identity, profile);
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(keypair, caps);
            Identity identity = Identity.Issue(iir, subjectId, 100, caps, Commons.IntermediateKeypair, Commons.IntermediateIdentity);
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Keypair.Generate(KeypairType.Identity));
            try {
                List<Capability> caps = new List<Capability> { Capability.Issue };
                Identity identity = Identity.Issue(iir, Guid.NewGuid(), 100, caps, Commons.TrustedKeypair, Commons.TrustedIdentity);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Keypair keypair = Keypair.Generate(KeypairType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = Identity.Issue(IdentityIssuingRequest.Generate(keypair, caps), Guid.NewGuid(), 100, caps, Commons.TrustedKeypair, Commons.TrustedIdentity);
            Assert.IsTrue(identity.HasCapability(Capability.Issue));
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
        }

        [TestMethod]
        public void IsSelfSignedTest1()
        {
            Identity.TrustedIdentity = null;
            Keypair keypair = Keypair.Generate(KeypairType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = Identity.Issue(IdentityIssuingRequest.Generate(keypair, caps), Guid.NewGuid(), 100, keypair);
            Assert.IsTrue(identity.IsSelfSigned());
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            List<Capability> caps = new List<Capability> { Capability.Generic };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Keypair.Generate(KeypairType.Identity));
            Identity identity = Identity.Issue(iir, Guid.NewGuid(), 100, caps, Commons.TrustedKeypair, Commons.TrustedIdentity);
            Assert.IsFalse(identity.IsSelfSigned());
        }

        [TestMethod]
        public void VerifyTrustTest1()
        {
            try 
            {
                Identity.TrustedIdentity = null;
                List<Capability> caps = new List<Capability> { Capability.Generic };
                Keypair keypair = Keypair.Generate(KeypairType.Identity);
                Identity identity = Identity.Issue(IdentityIssuingRequest.Generate(keypair), Guid.NewGuid(), 100, keypair);
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = Identity.Issue(IdentityIssuingRequest.Generate(Keypair.Generate(KeypairType.Identity)), Guid.NewGuid(), 100, caps, Commons.TrustedKeypair, Commons.TrustedIdentity);
            identity.Verify();
        }

        [TestMethod]
        public void VerifyTrustTest3()
        {
            Identity.TrustedIdentity = null;
            Capability[] caps = new Capability[1] { Capability.Generic };
            Keypair keypair = Keypair.Generate(KeypairType.Identity);
            Identity identity = Identity.Issue(IdentityIssuingRequest.Generate(keypair), Guid.NewGuid(), 100, keypair);
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            try {
                identity.Verify();
            } catch (UntrustedIdentityException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void VerifyTrustTest4()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Commons.IntermediateIdentity.Verify();
        }

        [TestMethod]
        public void ExportTest1()
        {
            Identity.TrustedIdentity = null;
            Capability[] caps = new Capability[1] { Capability.Generic };
            Keypair keypair = Crypto.GenerateKeyPair(1, KeypairType.Identity);
            Identity identity = Identity.Issue(IdentityIssuingRequest.Generate(keypair), Guid.NewGuid(), 100, keypair);
            string encoded = identity.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("I" + identity.Profile.ToString()));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 3);
        }

        [TestMethod]
        public void ImportTest1()
        {
            Identity.TrustedIdentity = null;
            string encoded = "I1.eyJzdWIiOiI4NTI0NWVlNS0wM2U1LTQ1ZGEtOGRhYi03YTA5MmRkYWMwNjIiLCJpc3MiOiIwODVmNTc4Yy0zMjRjLTQwOTctODRmOS1kN2E1ZmJlMTJkZTMiLCJpYXQiOjE2MjIzMjQ5NTksImV4cCI6MTY1Mzg2MDk1OSwiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQWRKYWJkRUJOYW83cjJYQWdIXHUwMDJCY1FsUFh6ZHMxLzlSdVlGQnpFenNBRHBCcyIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.STEuZXlKemRXSWlPaUl3T0RWbU5UYzRZeTB6TWpSakxUUXdPVGN0T0RSbU9TMWtOMkUxWm1KbE1USmtaVE1pTENKcGMzTWlPaUkzTm1FM1pEZzBPUzAzWTJSakxUUTRaamN0WVRkaU5pMDRNMk01WmpVek5USTFZV1VpTENKcFlYUWlPakUyTWpJek1qUTNNelVzSW1WNGNDSTZNVGM0TURBd05EY3pOU3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFWSkNNRlp5WW5vdllrZzVWakZCVEVwUVpqVktYSFV3TURKQ2VrVlFNVzQ0TVdOTk5UWmNkVEF3TWtJdmRqZFhPR1V4TUZWaklpd2lZMkZ3SWpwYkltZGxibVZ5YVdNaUxDSnBjM04xWlNKZGZRLnBVN2RjWTJPQzlvbS96NmNCQUllSjNteE9GNnNxditma1QreGVBOFhzM09uL00wNXI0MkJwcmJ1TDJldEZna1d2VU1BUlUyNlhPRXhDQW5xSUxoQkJB.tWRr2v6O6Je7vMhoBOUb6outlIO18DHc81ncN4hplc74OlWjRUZmtFbVRdNiPrgx5Gg+E+1Sb2LskNRIOMhADA";
            Identity identity = Identity.Import(encoded);
            Assert.IsNotNull(identity);
            Assert.AreEqual(identity.Profile, 1);
            Assert.AreEqual(new Guid("85245ee5-03e5-45da-8dab-7a092ddac062"), identity.SubjectId);
            Assert.AreEqual(1622324959, identity.IssuedAt);
            Assert.AreEqual(1653860959, identity.ExpiresAt);
            Assert.AreEqual(new Guid("085f578c-324c-4097-84f9-d7a5fbe12de3"), identity.IssuerId);
            Assert.AreEqual(identity.IdentityKey, "MCowBQYDK2VwAyEAdJabdEBNao7r2XAgH\u002BcQlPXzds1/9RuYFBzEzsADpBs");
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            Assert.AreEqual(new Guid("085f578c-324c-4097-84f9-d7a5fbe12de3"), identity.TrustChain.SubjectId);
        }

    }

}
