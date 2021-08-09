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
            //string k = key.Export();
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Issue };
            Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(subjectId, 100, caps,  key,  null);
            //Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 10, caps,  key,  null);
            //string id = identity.Export();
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
            string k = key.Export();
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            //List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify, Capability.Issue };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(key, caps);
            Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
            //Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 5, caps, Commons.TrustedKey, Commons.TrustedIdentity);
            string id = identity.Export();
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
        public void IsSelfSignedTest1()
        {
            Identity.SetTrustedIdentity(null);
            Key key = Key.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(key).IssueIdentity(Guid.NewGuid(), 100, null, key, null);
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
                List<Capability> caps = new List<Capability> { Capability.Generic };
                Key key = Key.Generate(KeyType.Identity);
                Identity identity = IdentityIssuingRequest.Generate(key).IssueIdentity(Guid.NewGuid(), 100, null, key, null);
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
            Capability[] caps = new Capability[1] { Capability.Generic };
            Key key = Key.Generate(KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(key).IssueIdentity(Guid.NewGuid(), 100, null, key, null);
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
            string exported = "Di:ID.eyJ1aWQiOiI1YjM2MGQwNy1mODY5LTRmZGItODBjNi00MzU2M2ZlZGU4ZjYiLCJzdWIiOiJmZDdkNmY1Yy01YzUxLTRkNmYtYmJjMy1iNDU5Mjc1Y2Q4NjMiLCJpc3MiOiJmNjhkMTVhYy04MjJkLTRmZGMtODFjYy04ZTUwYjQ3ODc3MmUiLCJpYXQiOiIyMDIxLTA4LTA5VDE4OjQxOjU3LjMwNjk1NVoiLCJleHAiOiIyMDIyLTA4LTA5VDE4OjQxOjU3LjMwNjk1NVoiLCJwdWIiOiIxaFBLaUo1V3ZoTFpTaGU3N3R1UWlOc2Y2c2t2SHJlZ1I2Ykx3d3liU1hhc3RQV1VIb1pjMSIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKMWFXUWlPaUl5T1RCa01XUm1ZaTB3TVdJMExUUXpPVFV0WW1FMVlpMWlObUkwTURGa1lXVXlNVFFpTENKemRXSWlPaUptTmpoa01UVmhZeTA0TWpKa0xUUm1aR010T0RGall5MDRaVFV3WWpRM09EYzNNbVVpTENKcGMzTWlPaUpqWTJVNU16azBNQzFoWm1OaUxUUmhZVEV0T1RBMk15MW1NR1l3WVRZellUVmxaREFpTENKcFlYUWlPaUl5TURJeExUQTRMVEE1VkRFd09qVXlPak16TGpBd056SXpPRm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE0VkRFd09qVXlPak16TGpBd056SXpPRm9pTENKd2RXSWlPaUl4YUZCS1NGazNhMk5aVlhSdGVIVmlRbU5CV0daS1dHOTVTMk54V0V3elJuTkVWVVJ1Vm10aVIwcG9VSGw1UzJoV2JsSnBWU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpTENKcGMzTjFaU0pkZlEuQVZXNFh4dVcyTWYrdVd4dG8zYmZpbGZhVi9FQWRMWVhnL3V6aW5pTFhKOFZQUDQveFNSTmVRYVQrcjJKQmY2WHFkK0JJTmdDbGNCTmhReDNxZU9xREFv.AQU4ijDHE23nHWhOzv7hoxq+NGSBjhjhz/j0q1wocScjChWG4016Fwcwb/WmEVoo5ImpSoOAc6Hvcj1ulFt7JAc";
            Identity identity = Item.Import<Identity>(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual(new Guid("5b360d07-f869-4fdb-80c6-43563fede8f6"), identity.UniqueId);
            Assert.AreEqual(new Guid("fd7d6f5c-5c51-4d6f-bbc3-b459275cd863"), identity.SubjectId);
            Assert.AreEqual(DateTime.Parse("2021-08-09T18:41:57.306955Z"), identity.IssuedAt);
            Assert.AreEqual(DateTime.Parse("2022-08-09T18:41:57.306955Z"), identity.ExpiresAt);
            Assert.AreEqual(new Guid("f68d15ac-822d-4fdc-81cc-8e50b478772e"), identity.IssuerId);
            Assert.AreEqual("1hPKiJ5WvhLZShe77tuQiNsf6skvHregR6bLwwybSXastPWUHoZc1", identity.PublicKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            identity.VerifyTrust();
        }

    }

}
