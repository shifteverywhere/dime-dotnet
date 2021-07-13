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
            Dime.SetTrustedIdentity(null);
            ProfileVersion profile = ProfileVersion.One;
            Guid subjectId = Guid.NewGuid();
            KeyBox keypair = KeyBox.Generate(KeyType.Identity, profile);
            //string key = keypair.ToString();
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Issue };
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, 100, caps,  keypair,  null);
            //Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, Dime.VALID_FOR_1_YEAR * 10, caps,  keypair,  null);
            //string id = identity.ToString();
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
            Guid subjectId = Guid.NewGuid();
            KeyBox keypair = KeyBox.Generate(KeyType.Identity, ProfileVersion.One);
            //string key = keypair.ToString();
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            //List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify, Capability.Issue };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(keypair, caps);
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, Dime.VALID_FOR_1_YEAR, caps, Commons.IntermediateKeybox, Commons.IntermediateIdentity);
            //Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, Dime.VALID_FOR_1_YEAR * 5, caps, Commons.TrustedKeypair, Commons.TrustedIdentity);
            //string id = identity.ToString();
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(identity.HasCapability(caps[1]));
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
                Identity identity = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity), reqCaps).IssueIdentity(Guid.NewGuid(), 100, allowCaps, Commons.TrustedKeybox, Commons.TrustedIdentity);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.TrustedKeybox, Commons.TrustedIdentity);
            Assert.IsTrue(identity.HasCapability(Capability.Issue));
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
        }

        [TestMethod]
        public void IsSelfSignedTest1()
        {
            Dime.SetTrustedIdentity(null);
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
            Assert.IsTrue(identity.IsSelfSigned);
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKeybox, Commons.IntermediateIdentity);
            Assert.IsFalse(identity.IsSelfSigned);
        }

        [TestMethod]
        public void VerifyTrustTest1()
        {
            try {
                Dime.SetTrustedIdentity(null);
                List<Capability> caps = new List<Capability> { Capability.Generic };
                KeyBox keypair = KeyBox.Generate(KeyType.Identity);
                Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
                Assert.IsTrue(identity.IsSelfSigned);
                identity.VerifyTrust();
            } catch (UntrustedIdentityException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void VerifyTrustTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKeybox, Commons.IntermediateIdentity);
            identity.VerifyTrust();
        }

        [TestMethod]
        public void VerifyTrustTest3()
        {
            Dime.SetTrustedIdentity(null);
            Capability[] caps = new Capability[1] { Capability.Generic };
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            try {
                identity.VerifyTrust();
            } catch (UntrustedIdentityException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void VerifyTrustTest4()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Commons.IntermediateIdentity.VerifyTrust();
        }

        [TestMethod]
        public void ExportTest1()
        {
            Dime.SetTrustedIdentity(null);
            Capability[] caps = new Capability[1] { Capability.Generic };
            KeyBox keypair = Crypto.GenerateKeyPair(ProfileVersion.One, KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
            string exported = identity.ToString();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Identity.IID));
            Assert.IsTrue(exported.Split(new char[] { '.' }).Length == 3);
        }

        [TestMethod]
        public void ImportTest1()
        {
            Dime.SetTrustedIdentity(null);
            string exported = "aW8uZGltZWZvcm1hdC5pZA.eyJ1aWQiOiIzZWFkMDJiNi1kNTRhLTQ4ODQtYThlYS0yZDVjMWQwZjFiYzAiLCJzdWIiOiJkNDY5NDU5YS1jMjdkLTQ3MzYtOWIwYS1lZDkzMTczZDliZWEiLCJpc3MiOiI0NWEzOGE2Mi1lODg4LTQ2Y2ItYmRiYy1hOWE2YWJhNmFjY2YiLCJpYXQiOjE2MjU4NjI1MDQsImV4cCI6MTY1NzM5ODUwNCwiaWt5IjoiQ1lIdDc0b3l5dnh2V3Z0Rkp2M3BoVndRVHdrTjZTNnBXYlRCb0VvSGdxZ2NCMmtuUlprdkRGIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoxYVdRaU9pSmpaRFkyTjJFMk9TMDBOR0l4TFRReU5HWXRZalF3T0MwMU1HWXlOemc0TUdOak9HSWlMQ0p6ZFdJaU9pSTBOV0V6T0dFMk1pMWxPRGc0TFRRMlkySXRZbVJpWXkxaE9XRTJZV0poTm1GalkyWWlMQ0pwYzNNaU9pSTNZekkxT0dWalpDMHpPRE5sTFRRMU5EVXRPR015WmkxbFkyRm1ObUU0Wm1ZeVlUQWlMQ0pwWVhRaU9qRTJNalU0TmpJek5EUXNJbVY0Y0NJNk1UYzRNelUwTWpNME5Dd2lhV3Q1SWpvaVExbElkRGN6UW1OV1RuTnlUbkpJVlVoRFMzcFljM00xTVZkamQzbDRPVzFoUnpOSWVqUnhWVGRhVW1KelduWktjMUpDY0VOaUlpd2lZMkZ3SWpwYkltZGxibVZ5YVdNaUxDSnBaR1Z1ZEdsbWVTSXNJbWx6YzNWbElsMTkuK0JYaWkvM3RYOFJ2TTBoVWVGVHlxS2c4Q0NGSlZLU1J6ZC8yamJhSkptMEhCVWlIZ3pmVzZIQnpvQkVWbmRsOGdFSHV3a2JUL0cxUEo2WU0vKzB5Q1E.Odwl3ot2NZw+5YqlrjTwXMTULGHq2vEpIco6p/KdCm+RspGHUY0gVI6CAnvXkb3oQBvZcTTBXYirGDUOHooZBQ";
            Identity identity = Identity.FromString(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual(new Guid("3ead02b6-d54a-4884-a8ea-2d5c1d0f1bc0"), identity.UID);
            Assert.AreEqual(new Guid("d469459a-c27d-4736-9b0a-ed93173d9bea"), identity.SubjectId);
            Assert.AreEqual(1625862504, identity.IssuedAt);
            Assert.AreEqual(1657398504, identity.ExpiresAt);
            Assert.AreEqual(new Guid("45a38a62-e888-46cb-bdbc-a9a6aba6accf"), identity.IssuerId);
            Assert.AreEqual("CYHt74oyyvxvWvtFJv3phVwQTwkN6S6pWbTBoEoHgqgcB2knRZkvDF", identity.IdentityKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsFalse(identity.HasCapability(Capability.Issue));
            Assert.IsNotNull(identity.TrustChain);
            Assert.AreEqual(new Guid("45a38a62-e888-46cb-bdbc-a9a6aba6accf"), identity.TrustChain.SubjectId);
        }

    }

}
