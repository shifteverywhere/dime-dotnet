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
            KeyBox keypair = KeyBox.Generate(KeyType.Identity, profile);
            //string key = keypair.Export();
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Issue };
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, 100, caps,  keypair,  null);
            //Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 10, caps,  keypair,  null);
            //string id = identity.Export();
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(subjectId == identity.IssuerId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(identity.HasCapability(caps[1]));
            Assert.IsTrue(identity.HasCapability(Capability.Self));
            Assert.IsTrue(keypair.PublicKey == identity.PublicKey);
            Assert.IsTrue(identity.IssuedAt != 0);
            Assert.IsTrue(identity.IssuedAt < identity.ExpiresAt);
            Assert.IsTrue(subjectId == identity.IssuerId);
        }

        [TestMethod]
        public void IssueTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Guid subjectId = Guid.NewGuid();
            KeyBox keypair = KeyBox.Generate(KeyType.Identity, Profile.Uno);
            //string key = keypair.Export();
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            //List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify, Capability.Issue };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(keypair, caps);
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR, caps, Commons.IntermediateKeybox, Commons.IntermediateIdentity);
            //Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 5, caps, Commons.TrustedKeybox, Commons.TrustedIdentity);
            //string id = identity.Export();
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(identity.HasCapability(caps[1]));
            Assert.IsTrue(keypair.PublicKey == identity.PublicKey);
            Assert.IsTrue(identity.IssuedAt != 0);
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
                Identity identity = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity), reqCaps).IssueIdentity(Guid.NewGuid(), 100, allowCaps, Commons.TrustedKeybox, Commons.TrustedIdentity);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.TrustedKeybox, Commons.TrustedIdentity);
            Assert.IsTrue(identity.HasCapability(Capability.Issue));
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
        }

        [TestMethod]
        public void IsSelfSignedTest1()
        {
            Identity.SetTrustedIdentity(null);
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
            Assert.IsTrue(identity.IsSelfSigned);
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKeybox, Commons.IntermediateIdentity);
            Assert.IsFalse(identity.IsSelfSigned);
        }

        [TestMethod]
        public void VerifyTrustTest1()
        {
            try {
                Identity.SetTrustedIdentity(null);
                List<Capability> caps = new List<Capability> { Capability.Generic };
                KeyBox keypair = KeyBox.Generate(KeyType.Identity);
                Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
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
            Identity identity = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKeybox, Commons.IntermediateIdentity);
            identity.VerifyTrust();
        }

        [TestMethod]
        public void VerifyTrustTest3()
        {
            Identity.SetTrustedIdentity(null);
            Capability[] caps = new Capability[1] { Capability.Generic };
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
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
            KeyBox keypair = Crypto.GenerateKeyBox(Profile.Uno, KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, caps, Commons.IntermediateKeybox, Commons.IntermediateIdentity);
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
            string exported = "Di:ID.eyJ1aWQiOiJjNDhlNGI2OC05MWFjLTRjOTMtYmE5Ni0xYzM1YzUwNzYxZDQiLCJzdWIiOiIzNGU3MDgxYi04ODcxLTQ2N2EtYTk2My03ZjBlZWRiNDJjODAiLCJpc3MiOiI2NDc1ODliZi03ZjdlLTRkNGMtODE3NC1lM2ViMzY2ZDVhOTEiLCJpYXQiOjE2MjYzNzg0OTYsImV4cCI6MTY1NzkxNDQ5NiwicHViIjoiQ1lIdDdnWVdqek54NXV6eWNmTjE4WVIxUjJMUEVmNTVoQWt1TkFCd0t3QXhBTkFia1pzOWR3IiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.SUQuZXlKMWFXUWlPaUprTWpjMVpESmpNeTAzWkRGbUxUUTBZVEV0T0Rjd1pTMHpPRFEyT1dWaU1EUmhORFVpTENKemRXSWlPaUkyTkRjMU9EbGlaaTAzWmpkbExUUmtOR010T0RFM05DMWxNMlZpTXpZMlpEVmhPVEVpTENKcGMzTWlPaUpqWVROaE1HWTFZeTAyTUdVeExUUmtZemd0WVRSaE9TMDNZVGd3T0Rrek5qTTVaV1lpTENKcFlYUWlPakUyTWpZek56Z3pNRFVzSW1WNGNDSTZNVGM0TkRBMU9ETXdOU3dpY0hWaUlqb2lRMWxJZERadFFXSldNemxwVG5kTVFrRkJWRTV0WTJaM2IwUTBWbTE1VUd0a2NFWldTa3RtU0RGTlJuSnpVRmN6WjNkMk1VcHlJaXdpWTJGd0lqcGJJbWRsYm1WeWFXTWlMQ0pwWkdWdWRHbG1lU0lzSW1semMzVmxJbDE5LkFhdmZLZzFXMTM1cndHamozMVZoNE5DMkM5N044QTE0ZDFWb1R1MGVnWElmK0s5N0lYdWxvYXJhY08zR1FUb044SHB2VjNMeVFPV0I2OHNnUHU1T3ZRcw.AavQrK+J3jQ+sEJKoFbh12aA0vhx4z7n3FijXsF9AOOLFNkmZSelEbdPxJ3A2VFrfHEaT5/GzB5LYcJ0jUbihgQ";
            Identity identity = Item.Import<Identity>(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual(new Guid("c48e4b68-91ac-4c93-ba96-1c35c50761d4"), identity.UID);
            Assert.AreEqual(new Guid("34e7081b-8871-467a-a963-7f0eedb42c80"), identity.SubjectId);
            Assert.AreEqual(1626378496, identity.IssuedAt);
            Assert.AreEqual(1657914496, identity.ExpiresAt);
            Assert.AreEqual(new Guid("647589bf-7f7e-4d4c-8174-e3eb366d5a91"), identity.IssuerId);
            Assert.AreEqual("CYHt7gYWjzNx5uzycfN18YR1R2LPEf55hAkuNABwKwAxANAbkZs9dw", identity.PublicKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            identity.VerifyTrust();
        }

    }

}
