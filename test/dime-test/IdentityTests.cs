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
using System.Text;
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
            //string key = keypair.Export();
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Issue };
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, 100, caps,  keypair,  null);
            //string id = identity.Export();
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
            KeyBox keypair = KeyBox.Generate(KeyType.Identity, profile);
            //string key = keypair.Export();
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(keypair, caps);
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, 100, caps, Commons.IntermediateKeypair, Commons.IntermediateIdentity);
            //string id = identity.Export();
            Assert.IsTrue(profile == identity.Profile);
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
                Identity identity = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity), reqCaps).IssueIdentity(Guid.NewGuid(), 100, allowCaps, Commons.TrustedKeypair, Commons.TrustedIdentity);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.TrustedKeypair, Commons.TrustedIdentity);
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
            Assert.IsTrue(identity.IsSelfSigned());
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKeypair, Commons.IntermediateIdentity);
            Assert.IsFalse(identity.IsSelfSigned());
        }

        [TestMethod]
        public void VerifyTrustTest1()
        {
            try {
                Dime.SetTrustedIdentity(null);
                List<Capability> caps = new List<Capability> { Capability.Generic };
                KeyBox keypair = KeyBox.Generate(KeyType.Identity);
                Identity identity = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 100, null, keypair, null);
                Assert.IsTrue(identity.IsSelfSigned());
                identity.Verify();
            } catch (UntrustedIdentityException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void VerifyTrustTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKeypair, Commons.IntermediateIdentity);
            identity.Verify();
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
            Assert.IsTrue(encoded.StartsWith(Dime.DIME_HEADER));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 4);
        }

        [TestMethod]
        public void ImportTest1()
        {
            Dime.SetTrustedIdentity(null);
            string encoded = "DI1.aW8uZGltZWZvcm1hdC5pZA.eyJzdWIiOiI1N2YxODEzYi0xZTNkLTQ2OGQtOTA0Mi0zNzg5ZTUzNDdlN2MiLCJpc3MiOiI5YWU4NDVmZi04NzQ3LTQyYWItYmRhYi1lYmMxNWM4OGE3N2QiLCJpYXQiOjE2MjMxODExODcsImV4cCI6MTY1NDcxNzE4NywiaWt5IjoiTUNvd0JRWURLMlZ3QXlFQXBxUnRIL051cXhKSmtmem1RRFFcdTAwMkJhYjV0NHZPZUNNVkoxczNxYjd0clJoMCIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.REkxLmFXOHVaR2x0WldadmNtMWhkQzVwWkEuZXlKemRXSWlPaUk1WVdVNE5EVm1aaTA0TnpRM0xUUXlZV0l0WW1SaFlpMWxZbU14TldNNE9HRTNOMlFpTENKcGMzTWlPaUkzTlRBME5qQTNNaTAxTWpZNExUUTFaVGd0WW1WaE5TMDJaRFF4T1dFNU5tSXlOakVpTENKcFlYUWlPakUyTWpNeE9EQTRNVGNzSW1WNGNDSTZNVGM0TURnMk1EZ3hOeXdpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXdHRabFZXUm5nMlpUQlpia2xwT1ZWYWIxUXlVVkpFTkdaRFF6STBWV0pSWkhsMWJITjRiWGRjZFRBd01rSktWU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVhOemRXVWlYWDAudytLMEw2MEJuZ3VCYmx6M3ZkcWdJK2dnMG9DWXF1eHFVNjBQTTVkS1RTR1Njb1BibDU3MlFzS3JtVTFvd0ZqV0t3N3RQVTVwcGVRZSswb2FyU0pKRGc.hnWfWuQMjkyRNdnEyM+7OffJUjL6t7AwDA8qWipnAzbZUIDIoQafF2W1gDTxSD0DRy9q7saBDfQgAdY7aXbDDg";
            Identity identity = Dime.Import<Identity>(encoded);
            Assert.IsNotNull(identity);
            Assert.AreEqual(ProfileVersion.One, identity.Profile);
            Assert.AreEqual(new Guid("57f1813b-1e3d-468d-9042-3789e5347e7c"), identity.SubjectId);
            Assert.AreEqual(1623181187, identity.IssuedAt);
            Assert.AreEqual(1654717187, identity.ExpiresAt);
            Assert.AreEqual(new Guid("9ae845ff-8747-42ab-bdab-ebc15c88a77d"), identity.IssuerId);
            Assert.AreEqual("MCowBQYDK2VwAyEApqRtH/NuqxJJkfzmQDQ\u002Bab5t4vOeCMVJ1s3qb7trRh0", identity.IdentityKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            Assert.AreEqual(new Guid("9ae845ff-8747-42ab-bdab-ebc15c88a77d"), identity.TrustChain.SubjectId);
        }
/*
TODO: uncomment once attachments are implemented (again)
       [TestMethod]
        public void AttachmentTest1()
        {
            KeyBox key = KeyBox.Generate(KeyType.Exchange);
            Attachment attachment = new Attachment();
            attachment.AddItem(Encoding.UTF8.GetBytes(key.Export()));
            Identity sender = Commons.SenderIdentity;
            sender.Attachment = attachment;
        }

       [TestMethod]
        public void AttachmentTest2()
        {
            Attachment attachment = new Attachment();
            attachment.AddItem(Encoding.UTF8.GetBytes(KeyBox.Generate(KeyType.Exchange).Export()));
            attachment.Seal(Commons.SenderKeypair.Key);
            Identity sender = Commons.SenderIdentity;
            sender.Attachment = attachment;
            string encoded = sender.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("I" + (int)attachment.Profile));
            string[] parts = encoded.Split(new char[] { ':' });
            Assert.IsTrue(parts.Length == 2);
            Assert.IsTrue(parts[1].StartsWith("a" + (int)attachment.Profile));
        }

        [TestMethod]
        public void AttachmentTest3()
        {
            Attachment attachment = new Attachment();
            attachment.AddItem(Encoding.UTF8.GetBytes(KeyBox.Generate(KeyType.Exchange).Export()));
            Identity sender = Commons.SenderIdentity;
            sender.Attachment = attachment;
            try {
                sender.Export();
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void AttachmentTest4()
        {
            KeyBox[] keysIn = new KeyBox[3] { KeyBox.Generate(KeyType.Exchange), 
                                              KeyBox.Generate(KeyType.Exchange), 
                                              KeyBox.Generate(KeyType.Exchange) };
            Attachment attachment = new Attachment();
            attachment.AddItem(Encoding.UTF8.GetBytes(keysIn[0].Export()));
            attachment.AddItem(Encoding.UTF8.GetBytes(keysIn[1].Export()));
            attachment.AddItem(Encoding.UTF8.GetBytes(keysIn[2].Export()));
            attachment.Seal(Commons.SenderKeypair.Key);
            Identity sender1 = Commons.SenderIdentity;
            Commons.SenderIdentity.Attachment = attachment;
            string encoded = sender1.Export();
            
            Identity sender2 = Dime.Import<Identity>(encoded);
            Assert.IsTrue(sender2.Attachment.Items.Count == 3);
            KeyBox[] keysOut = new KeyBox[3];
            for (int i = 0; i < 3; i++)
            {
                byte[] keyBytes = sender2.Attachment.Items[i];
                keysOut[i] = Dime.Import<KeyBox>(System.Text.Encoding.UTF8.GetString(keyBytes, 0, keyBytes.Length));
                Assert.AreEqual(keysIn[i].Id, keysOut[i].Id);
                Assert.AreEqual(keysIn[i].Type, keysOut[i].Type);
                Assert.AreEqual(keysIn[i].Key, keysOut[i].Key);
                Assert.AreEqual(keysIn[i].PublicKey, keysOut[i].PublicKey);
            }
        }
*/
    }

}
