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
            //string key = keypair.Encoded;
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Issue };
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, 100, caps,  keypair,  null); // Dime.VALID_FOR_1_YEAR * 10
            //string id = identity.Encoded;
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
            //string key = keypair.Encoded;
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(keypair, caps);
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, Dime.VALID_FOR_1_YEAR, caps, Commons.IntermediateKeypair, Commons.IntermediateIdentity);
            //string id = identity.Encoded;
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
            Assert.IsTrue(identity.IsSelfSigned);
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(KeyBox.Generate(KeyType.Identity)).IssueIdentity(Guid.NewGuid(), 100, caps, Commons.IntermediateKeypair, Commons.IntermediateIdentity);
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
            string exported = identity.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Dime.HEADER));
            Assert.IsTrue(exported.Split(new char[] { '.' }).Length == 3);
        }

        [TestMethod]
        public void ImportTest1()
        {
            Dime.SetTrustedIdentity(null);
            string encoded = "DiME:aW8uZGltZWZvcm1hdC5pZA.eyJ2ZXIiOjEsInVpZCI6Ijg0NjE0YjU0LWE2NGUtNGU2Zi04ODhmLTUwMzliOWZhNjRmYyIsInN1YiI6ImFkZDIwZmY0LTMyMmItNGQ1NC1iYzc0LWJjYjVjN2VhMDhkNiIsImlzcyI6ImNmOWRlMjMxLTdkYmQtNDA0OS04MDFhLTBiZDUzMjE0ZTMzNSIsImlhdCI6MTYyMzI3NjI4OSwiZXhwIjoxNjU0ODEyMjg5LCJpa3kiOiJNQ293QlFZREsyVndBeUVBcDgyMFx1MDAyQnhlUWhZZFFlM3pMSjRObFNNR3hKOFhLOS9OOHVaZDJnOHZBSlZnIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoyWlhJaU9qRXNJblZwWkNJNklqQTVNelExTVdSaUxUSTJaakl0TkRCak5TMDRabVE1TFRZM00yVTFaalV3WVRZNU5DSXNJbk4xWWlJNkltTm1PV1JsTWpNeExUZGtZbVF0TkRBME9TMDRNREZoTFRCaVpEVXpNakUwWlRNek5TSXNJbWx6Y3lJNklqRTNaVFppTnpnM0xXUTJaV1l0TkRFMU9DMWhZak01TFRoaU5XWmpNamczTlRjelpTSXNJbWxoZENJNk1UWXlNekkzTkRRNE55d2laWGh3SWpveE56Z3dPVFUwTkRnM0xDSnBhM2tpT2lKTlEyOTNRbEZaUkVzeVZuZEJlVVZCUlZsd2JXbGxiRTUzYmtSNlpHTkphbWxMYlVaUFZURjFabWRuVEhGWk9XZFZORk4zYUU1NWN6TXhTU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVhOemRXVWlYWDAuc0pJZXZZYjcybWppRTdXOHZPS3Ywbmk5MGUzSVhhd1lsOGZuWVhsMzRJbzRlUU1tZ05DYkdUN1N2MXFIclBhcjIxZ1FkZGVVQUdZaFVzM1hwbFIyQWc.revzfv1JwJG3/m/IKY3bVm5VFxMB/epmfe/0gqxhXD0rbUdvj+j22QLhuyhKqRe1XScOypk+TiwZ2RW0BKEUAA";
            Identity identity = Dime.Import<Identity>(encoded);
            Assert.IsNotNull(identity);
            Assert.AreEqual(ProfileVersion.One, identity.Profile);
            Assert.AreEqual(new Guid("84614b54-a64e-4e6f-888f-5039b9fa64fc"), identity.Id);
            Assert.AreEqual(new Guid("add20ff4-322b-4d54-bc74-bcb5c7ea08d6"), identity.SubjectId);
            Assert.AreEqual(1623276289, identity.IssuedAt);
            Assert.AreEqual(1654812289, identity.ExpiresAt);
            Assert.AreEqual(new Guid("cf9de231-7dbd-4049-801a-0bd53214e335"), identity.IssuerId);
            Assert.AreEqual("MCowBQYDK2VwAyEAp820\u002BxeQhYdQe3zLJ4NlSMGxJ8XK9/N8uZd2g8vAJVg", identity.IdentityKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            Assert.AreEqual(new Guid("cf9de231-7dbd-4049-801a-0bd53214e335"), identity.TrustChain.SubjectId);
        }

    }

}
