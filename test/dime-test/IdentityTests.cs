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
            Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(Commons.METHOD_NAME, subjectId, 100, caps,  key,  null);
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
            //string k = key.Export();
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            //List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify, Capability.Issue };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(key, caps);
            Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(Commons.METHOD_NAME, subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
            //Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 5, caps, Commons.TrustedKey, Commons.TrustedIdentity);
            //string id = identity.Export();
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
                Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), reqCaps).IssueIdentity(Commons.METHOD_NAME, Guid.NewGuid(), 100, allowCaps, Commons.TrustedKey, Commons.TrustedIdentity);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Key key = Key.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(Commons.METHOD_NAME, Guid.NewGuid(), 100, caps, Commons.TrustedKey, Commons.TrustedIdentity);
            Assert.IsTrue(identity.HasCapability(Capability.Issue));
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
        }

        [TestMethod]
        public void IsSelfSignedTest1()
        {
            Identity.SetTrustedIdentity(null);
            Key key = Key.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(key).IssueIdentity(Commons.METHOD_NAME, Guid.NewGuid(), 100, null, key, null);
            Assert.IsTrue(identity.IsSelfSigned);
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity)).IssueIdentity(Commons.METHOD_NAME, Guid.NewGuid(), 100, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
            Assert.IsFalse(identity.IsSelfSigned);
        }

        [TestMethod]
        public void VerifyTrustTest1()
        {
            try {
                Identity.SetTrustedIdentity(null);
                List<Capability> caps = new List<Capability> { Capability.Generic };
                Key key = Key.Generate(KeyType.Identity);
                Identity identity = IdentityIssuingRequest.Generate(key).IssueIdentity(Commons.METHOD_NAME, Guid.NewGuid(), 100, null, key, null);
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
            Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity)).IssueIdentity(Commons.METHOD_NAME, Guid.NewGuid(), 100, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
            identity.VerifyTrust();
        }

        [TestMethod]
        public void VerifyTrustTest3()
        {
            Identity.SetTrustedIdentity(null);
            Capability[] caps = new Capability[1] { Capability.Generic };
            Key key = Key.Generate(KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(key).IssueIdentity(Commons.METHOD_NAME, Guid.NewGuid(), 100, null, key, null);
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
            Identity identity = IdentityIssuingRequest.Generate(key, caps).IssueIdentity(Commons.METHOD_NAME, Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, caps, Commons.IntermediateKey, Commons.IntermediateIdentity);
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
            string exported = "Di:ID.eyJ1aWQiOiI1OWVlMThkOC0yYTU0LTQ2ZDUtYTEwNy1kZDJkMTg0NjgzMWYiLCJzdWIiOiI4MTBkY2FjZS1jODNkLTRmMjQtYmY1NS0xZjVjNzVlOTEyYTYiLCJpc3MiOiJkZDNjZmQ2ZS1hMzY2LTRiMGMtYTRlMy1hZTExZjdjZGY5NjciLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjMxOjU2LjU0NzAwMVoiLCJleHAiOiIyMDIyLTA4LTEwVDA2OjMxOjU2LjU0NzAwMVoiLCJwdWIiOiIxaFBLUG1pWVd4UzdlU2d2NTdiTE1ab1hHWXp6M0d0UXY1OG1HMWNGaW9zTTlLZVFoMTZmNyIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKMWFXUWlPaUkwTldVMU1qQXhOeTB3WldJeUxUUTVOamN0T0RVeFlTMW1OVGd5WlRJMlpqUm1aak1pTENKemRXSWlPaUprWkROalptUTJaUzFoTXpZMkxUUmlNR010WVRSbE15MWhaVEV4WmpkalpHWTVOamNpTENKcGMzTWlPaUl3TUdGaE1qWmxOeTB6TkdJeUxUUm1ZVEl0WW1SbU5pMHhOMlpsWXpBNE5EQTNOamtpTENKcFlYUWlPaUl5TURJeExUQTRMVEV3VkRBMk9qRTVPalV6TGpnd01qVTFNVm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE1VkRBMk9qRTVPalV6TGpnd01qVTFNVm9pTENKd2RXSWlPaUl4YUZCTGRVVkZPSEpNYmpSd05rNUlkWG96VG1wR1VWUm1OalJWTmtoUk4wcDZPR1J4T0ZKdFdVNUNURFozVGxZelRrRnlReUlzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpTENKcGMzTjFaU0pkZlEuQVpmM1dGU29mNkRYTkhtd0ZiYUFWR2p2c09xcFhhZ1JSWnhWV0tlYW03U3graThjdDEzRmtGbVdRMk4vbGZuVHpZTTQ0dTNPc2RORVVGd3hQbmdPSHc0.ARioMUrbIZFv2N7c5bDkGgGLlUAXdXWWu72hzQidzyWH1w5GQvXn9SlDqO/mwLdEnD7FAj0L56DHmiiKc5dTJAQ";
            Identity identity = Item.Import<Identity>(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual(new Guid("59ee18d8-2a54-46d5-a107-dd2d1846831f"), identity.UniqueId);
            Assert.AreEqual(new Guid("810dcace-c83d-4f24-bf55-1f5c75e912a6"), identity.SubjectId);
            Assert.AreEqual(DateTime.Parse("2021-08-10T06:31:56.547001Z"), identity.IssuedAt);
            Assert.AreEqual(DateTime.Parse("2022-08-10T06:31:56.547001Z"), identity.ExpiresAt);
            Assert.AreEqual(new Guid("dd3cfd6e-a366-4b0c-a4e3-ae11f7cdf967"), identity.IssuerId);
            Assert.AreEqual("1hPKPmiYWxS7eSgv57bLMZoXGYzz3GtQv58mG1cFiosM9KeQh16f7", identity.PublicKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            identity.VerifyTrust();
        }

    }

}
