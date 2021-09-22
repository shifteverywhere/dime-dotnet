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
            Identity identity = iir.Issue(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
            //Identity identity = iir.Issue(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 5, caps, Commons.TrustedKey, Commons.TrustedIdentity);
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
                Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), reqCaps).Issue(Guid.NewGuid(), 100, allowCaps, Commons.TrustedKey, Commons.TrustedIdentity);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Key key = Key.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(key, caps).Issue(Guid.NewGuid(), 100, caps, Commons.TrustedKey, Commons.TrustedIdentity);
            Assert.IsTrue(identity.HasCapability(Capability.Issue));
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
        }

       [TestMethod]
        public void IssueTest5()
        {
            Identity.SetTrustedIdentity(null);
            List<Capability> caps = new List<Capability> { Capability.Issue };
            try {
                Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), caps).Issue(Guid.NewGuid(), 100, caps, Commons.TrustedKey, null);
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
            Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity)).Issue(Guid.NewGuid(), 100, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
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
            Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity)).Issue(Guid.NewGuid(), 100, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
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
            Identity identity = IdentityIssuingRequest.Generate(key, caps).Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
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
            string exported = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiODhiMWYyYTAtNTZjNi00MTZmLWI0OWQtNGY1NThjMjcxMmU0Iiwic3ViIjoiNGRlZjk4NTEtMWJlNy00YzJiLTljMGQtMjY3M2U3MTJjMDQ1IiwiaXNzIjoiOTEyZWQ5YmEtYTcxYi00MDRjLWFhYjgtOTViNzI5ZTgxZjRjIiwiaWF0IjoiMjAyMS0wOS0yMlQxODoxNzoxMS4zMDM5NDNaIiwiZXhwIjoiMjAyMi0wOS0yMlQxODoxNzoxMS4zMDM5NDNaIiwicHViIjoiMWhQS0paWVlBSFV5OWNpdFB0VXZFWGRaNEE4SjRyUVMySHlSQ2Z4ZHlhdnF0VXg0MnRyNEQiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1UWXhZelEzWkdJdE1UYzJPQzAwTkdJMExUaGhPVEF0WkdSaE9XRmlaVGRpWW1Oaklpd2ljM1ZpSWpvaU9URXlaV1E1WW1FdFlUY3hZaTAwTURSakxXRmhZamd0T1RWaU56STVaVGd4WmpSaklpd2lhWE56SWpvaVlXVTJNbVJtTnpJdE16UTVNUzAwTTJFd0xXRmhPVEF0TVRrelpUUmhNVFF3TTJRNElpd2lhV0YwSWpvaU1qQXlNUzB3T1Mwd05sUXdPRG93TmpvME5TNDNOakUyTTFvaUxDSmxlSEFpT2lJeU1ESTJMVEE1TFRBMVZEQTRPakEyT2pRMUxqYzJNVFl6V2lJc0luQjFZaUk2SWpGb1VFdFpTbVI2Tm5ReE5VNTNOemt6ZDBoT1pGUnBXV2hGZFdzelZtbFVlV1ZxZEVWNlZrdHhVVEYwWjFkcllWSk1iemw0SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5BYW4vdWJwY1gzL2pMK3d1QmpTWi9IT2VSSDlLVFpNZ0VNTWZmVGpSZUMwRzEwRXhyaVVmazZjRUZPOUhsM0hlQ1NaQ1NuWWR5Y0ErU09qNlpRK2hud1E.AUypvM3PVgq5jMGgzAlWhYRf4msby3FM5jW68mB1yS+aO8rg9b7NnSlTm/7vJHo5pWD/17u3sptUAz68SGwCqwg";
            Identity identity = Item.Import<Identity>(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual(Commons.SYSTEM_NAME, identity.SystemName);
            Assert.AreEqual(new Guid("88b1f2a0-56c6-416f-b49d-4f558c2712e4"), identity.UniqueId);
            Assert.AreEqual(new Guid("4def9851-1be7-4c2b-9c0d-2673e712c045"), identity.SubjectId);
            Assert.AreEqual(DateTime.Parse("2021-09-22T18:17:11.303943Z"), identity.IssuedAt);
            Assert.AreEqual(DateTime.Parse("2022-09-22T18:17:11.303943Z"), identity.ExpiresAt);
            Assert.AreEqual(Commons.IntermediateIdentity.SubjectId, identity.IssuerId);
            Assert.AreEqual("1hPKJZYYAHUy9citPtUvEXdZ4A8J4rQS2HyRCfxdyavqtUx42tr4D", identity.PublicKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            identity.VerifyTrust();
        }

    }

}
