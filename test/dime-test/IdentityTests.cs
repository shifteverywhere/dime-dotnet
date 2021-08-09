//
//  IdentityTests.cs
//  DiME - Digital Identity Message Envelope
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
            string exported = "Di:ID.eyJ1aWQiOiI3ZDZhNTVlOC0yMWJhLTQ4MGMtOGFmNi1iNGE0NGYwMjRmYWUiLCJzdWIiOiI5NzNhNmI2My02MjRhLTQwYjktYjNjZi1hMDU1MTljODVhZWYiLCJpc3MiOiI0OTdkMTU2Ny1kMTBhLTRiNWYtOGIwOS00YmQ5NDc3ZTQyOTUiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjE2OjMxLjAyMzE5M1oiLCJleHAiOiIyMDIyLTA4LTA5VDEwOjE2OjMxLjAyMzE5M1oiLCJwdWIiOiJDWUh0N1pmSnlnZXloOWdtNUV3Z0s5NUVWanJvRE4xQzZlV2JpY0pCc0ZuTjJnaUN1VEJNRk4iLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKMWFXUWlPaUkyWmpVek4yUXlZUzB3TWpKaUxUUmhNR1F0WWpVNFl5MHlNRFZqT1dRd01XRXpOelFpTENKemRXSWlPaUkwT1Rka01UVTJOeTFrTVRCaExUUmlOV1l0T0dJd09TMDBZbVE1TkRjM1pUUXlPVFVpTENKcGMzTWlPaUpoWXpZMFlXTm1aaTFrTXpCbUxUUXdNVEF0WWprMk5TMHpOVEZoTVRkbE1URTBOMllpTENKcFlYUWlPaUl5TURJeExUQTRMVEE1VkRBNU9qVXhPakkwTGpjM016azJPVm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE0VkRBNU9qVXhPakkwTGpjM016azJPVm9pTENKd2RXSWlPaUpEV1VoME4zSk5RV3Q2TVUxU1FrSjJRbkUwVFhOTVJWSnZRVVZpTjJSMlZ6STJXa05yTjFaVFZsWlZhRmRwWTFOcmNrSlNhVVFpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLkFRdFFuaUZ2My9mMXlod1p0ZjZxcCtoZVVpaW9sdlVnYUp3TzFMWjIrcTJydG1tWGtQNC9xenp0Vms5a1ZOZE1KYzRFdFVjTVlaOTEzWXJydEpudnpnWQ.AUInSyL4AsrkXLFGC5M5yPp0rF7zUVGk4GC6p9wNiefueZSTEatN0mBE4ePXfFqDW4WnFHUnLtpnmsO45W0+uQw";
            Identity identity = Item.Import<Identity>(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual(new Guid("7d6a55e8-21ba-480c-8af6-b4a44f024fae"), identity.UniqueId);
            Assert.AreEqual(new Guid("973a6b63-624a-40b9-b3cf-a05519c85aef"), identity.SubjectId);
            Assert.AreEqual(DateTime.Parse("2021-08-09T10:16:31.023193Z"), identity.IssuedAt);
            Assert.AreEqual(DateTime.Parse("2022-08-09T10:16:31.023193Z"), identity.ExpiresAt);
            Assert.AreEqual(new Guid("497d1567-d10a-4b5f-8b09-4bd9477e4295"), identity.IssuerId);
            Assert.AreEqual("CYHt7ZfJygeyh9gm5EwgK95EVjroDN1C6eWbicJBsFnN2giCuTBMFN", identity.PublicKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            identity.VerifyTrust();
        }

    }

}
