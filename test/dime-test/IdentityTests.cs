//
//  IdentityTests.cs
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
    public class IdentityTests
    {

        [TestMethod]
        public void IssueTest1()
        {
            Identity.SetTrustedIdentity(null);
            Profile profile = Profile.Uno;
            Guid subjectId = Guid.NewGuid();
            Key key = Key.Generate(KeyType.Identity, -1, profile);            
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Issue };
            Identity identity = IdentityIssuingRequest.Generate(key, caps).SelfIssue(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 10, key, Commons.SYSTEM_NAME);
//            string k = key.Export();
//            string i = identity.Export();
            Assert.AreEqual(Commons.SYSTEM_NAME, identity.SystemName);
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(subjectId == identity.IssuerId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(identity.HasCapability(caps[1]));
            Assert.IsTrue(identity.HasCapability(Capability.Self));
            Assert.IsTrue(key.Public == identity.PublicKey);
            Assert.IsNotNull(identity.IssuedAt);
            Assert.IsNotNull(identity.ExpiresAt);
            Assert.IsTrue(identity.IssuedAt < identity.ExpiresAt);
            Assert.IsTrue(subjectId == identity.IssuerId);
        }

        [TestMethod]
        public void IssueTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Guid subjectId = Guid.NewGuid();
            Key key = Key.Generate(KeyType.Identity, -1, Profile.Uno);
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            //List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify, Capability.Issue };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(key, caps);
            Identity identity = iir.IssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
            //Identity identity = iir.IssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 5, caps, Commons.TrustedKey, Commons.TrustedIdentity);
            string k = key.Export();
            string i = identity.Export();
            Assert.AreEqual(Identity.TrustedIdentity.SystemName, identity.SystemName);
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(identity.HasCapability(caps[1]));
            Assert.IsTrue(key.Public == identity.PublicKey);
            Assert.IsNotNull(identity.IssuedAt);
            Assert.IsNotNull(identity.ExpiresAt);
            Assert.IsTrue(identity.IssuedAt < identity.ExpiresAt);
            Assert.IsTrue(Commons.IntermediateIdentity.SubjectId == identity.IssuerId);
        }

       [TestMethod]
        public void IssueTest3()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> reqCaps = new List<Capability> { Capability.Issue };
            List<Capability> allowCaps = new List<Capability> { Capability.Generic, Capability.Identify };
            try {
                Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), reqCaps).IssueIdentity(Guid.NewGuid(), 100, allowCaps, Commons.TrustedKey, Commons.TrustedIdentity);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Key key = Key.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.TrustedKey, Commons.TrustedIdentity);
            Assert.IsTrue(identity.HasCapability(Capability.Issue));
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
        }

       [TestMethod]
        public void IssueTest5()
        {
            Identity.SetTrustedIdentity(null);
            List<Capability> caps = new List<Capability> { Capability.Issue };
            try {
                Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), caps).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.TrustedKey, null);
            } catch (ArgumentNullException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSelfSignedTest1()
        {
            Identity.SetTrustedIdentity(null);
            Key key = Key.Generate(KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100, key, Commons.SYSTEM_NAME);
            Assert.IsTrue(identity.IsSelfSigned);
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
            Assert.IsFalse(identity.IsSelfSigned);
        }

        [TestMethod]
        public void VerifyTrustTest1()
        {
            try {
                Identity.SetTrustedIdentity(null);
                Key key = Key.Generate(KeyType.Identity);
                Identity identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100, key, Commons.SYSTEM_NAME);
                Assert.IsTrue(identity.IsSelfSigned);
                identity.VerifyTrust();
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void VerifyTrustTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
            identity.VerifyTrust();
        }

        [TestMethod]
        public void VerifyTrustTest3()
        {
            Identity.SetTrustedIdentity(null);
            Key key = Key.Generate(KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100, key, Commons.SYSTEM_NAME);
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            try {
                identity.VerifyTrust();
            } catch (UntrustedIdentityException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void VerifyTrustTest4()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Commons.IntermediateIdentity.VerifyTrust();
        }

        [TestMethod]
        public void ExportTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            Key key = Crypto.GenerateKeyBox(Profile.Uno, KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
            string exported = identity.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith($"{Envelope.HEADER}:{Identity.TAG}"));
            Assert.AreEqual(4, exported.Split(new char[] { '.' }).Length);
        }

        [TestMethod]
        public void ImportTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            string exported = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiOWVjNDdlY2ItYmQ3Mi00NzZhLTkzMDAtMzIxYzE1MjZmMjE5Iiwic3ViIjoiMWMxNDQ1YWMtODZjZC00MjMyLWEyODQtMzE2ZWFmODVlZjU1IiwiaXNzIjoiNWU2OWQ5NDgtMmZlMC00Y2NmLTg2ZTUtNTFhYTNhYTY3YjZmIiwiaWF0IjoiMjAyMS0wOC0xMVQwNzo0MjoxMi41NzkwODRaIiwiZXhwIjoiMjAyMi0wOC0xMVQwNzo0MjoxMi41NzkwODRaIiwicHViIjoiMWhQSk5OcXdweUE5c3UydnFIdDRjU0xkckVvTDNUZjlrNzJVbWpWZ1pKSExwaDVlM25oZngiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1UTmtOV1ZpTXpBdFpHSmxaUzAwWmpjNExUZzNaVEF0T0RjNVptVmhZVEl5WkRCaklpd2ljM1ZpSWpvaU5XVTJPV1E1TkRndE1tWmxNQzAwWTJObUxUZzJaVFV0TlRGaFlUTmhZVFkzWWpabUlpd2lhWE56SWpvaVl6YzNZamcxWm1ZdFpHUTNaQzAwWTJVeExUaGpZak10WTJNeVlqWm1ZbVprWW1GaElpd2lhV0YwSWpvaU1qQXlNUzB3T0MweE1WUXdOem96T1RvMU55NHdPREkzTWpOYUlpd2laWGh3SWpvaU1qQXlOaTB3T0MweE1GUXdOem96T1RvMU55NHdPREkzTWpOYUlpd2ljSFZpSWpvaU1XaFFTMEUyUmxSdmJ6WTRhbWhCYm5CVlFsQkZTa1IzYlhaQlVIcGxOMUYxT0UxM2FGTjJSMUJrYm5SS09YSm9VM3BVU25FaUxDSmpZWEFpT2xzaVoyVnVaWEpwWXlJc0ltbGtaVzUwYVdaNUlpd2lhWE56ZFdVaVhYMC5BWXNqbmZvVnZqaDdZSVJWTCs0MlJQTkFDQWpwZ3c5aTRMd281WmdtN3FjOEM5V2FWZFgwMnV1cXlQNm9yeEExUTdubjBsV2E5Rlc0VldPRGhWZnJVd3M.AU9diJ5eJ0/3/6EdaBlYBlJzPMDsebkU8uFsAYDO3RsZLwXdwqy6mM2GjCvHranqbC50YG9kLKwaz4VPa96aUgk";
            Identity identity = Item.Import<Identity>(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual(Commons.SYSTEM_NAME, identity.SystemName);
            Assert.AreEqual(new Guid("9ec47ecb-bd72-476a-9300-321c1526f219"), identity.UniqueId);
            Assert.AreEqual(new Guid("1c1445ac-86cd-4232-a284-316eaf85ef55"), identity.SubjectId);
            Assert.AreEqual(DateTime.Parse("2021-08-11T07:42:12.579084Z"), identity.IssuedAt);
            Assert.AreEqual(DateTime.Parse("2022-08-11T07:42:12.579084Z"), identity.ExpiresAt);
            Assert.AreEqual(Commons.IntermediateIdentity.SubjectId, identity.IssuerId);
            Assert.AreEqual("1hPJNNqwpyA9su2vqHt4cSLdrEoL3Tf9k72UmjVgZJHLph5e3nhfx", identity.PublicKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            identity.VerifyTrust();
        }

    }

}
