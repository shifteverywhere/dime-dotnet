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
            Assert.IsTrue(keypair.PublicKey == identity.PublicKey);
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
            string key = keypair.ToString();
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            //List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify, Capability.Issue };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(keypair, caps);
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, Dime.VALID_FOR_1_YEAR, caps, Commons.IntermediateKeybox, Commons.IntermediateIdentity);
            //Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(subjectId, Dime.VALID_FOR_1_YEAR * 5, caps, Commons.TrustedKeybox, Commons.TrustedIdentity);
            string id = identity.ToString();
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
        public void ToStringTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            KeyBox keypair = Crypto.GenerateKeyPair(ProfileVersion.One, KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(keypair, caps).IssueIdentity(Guid.NewGuid(), Dime.VALID_FOR_1_YEAR, caps, Commons.IntermediateKeybox, Commons.IntermediateIdentity);
            string exported = identity.ToString();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Identity.IID));
            Assert.AreEqual(4, exported.Split(new char[] { '.' }).Length);
        }

        [TestMethod]
        public void FromStringTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            string exported = "aWQ.eyJ1aWQiOiI3N2MzNjA2Ny0wYWE2LTQwNGUtODYwYy0zYTYxMWQ4ZDdjZDciLCJzdWIiOiI4ZDUxMjkyMy04NzI3LTQyNzYtYjkzOS05NWI1YmRiMGVjN2MiLCJpc3MiOiIwMzdkOTEzNS1mNmVhLTQ1ZTEtOWFhNi1hNmQ0NzE3NmUwMGQiLCJpYXQiOjE2MjYyMTQyMzcsImV4cCI6MTY1Nzc1MDIzNywicHViIjoiQ1lIdDg0R1Z3bkZxa21ZUk00c3BpQzdDYldzY3pBYzViQ0tqWVdwS2NYUDl5R3hHOUR4QXltIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVdRLmV5SjFhV1FpT2lKbU5ERTFaR00wTUMxak1UYzJMVFJqWTJZdE9EaGhOeTFoTW1NeE5USTJOemhsTkRBaUxDSnpkV0lpT2lJd016ZGtPVEV6TlMxbU5tVmhMVFExWlRFdE9XRmhOaTFoTm1RME56RTNObVV3TUdRaUxDSnBjM01pT2lJM05USTVabUkwWlMxalpqTTRMVFJoTnpBdFlqY3dNUzAwT1dVNVltTTVaVGc1TWpFaUxDSnBZWFFpT2pFMk1qWXlNVE0zTnpRc0ltVjRjQ0k2TVRjNE16ZzVNemMzTkN3aWNIVmlJam9pUTFsSWREY3pOazVvZFVSV2VYZEtZemRXVG5KNVRrSk9iak5ZZG01V09UWnpWRXBuYUhGR1ZsaGtZa3RZYVZGcWJYbHdWMWg0SWl3aVkyRndJanBiSW1kbGJtVnlhV01pTENKcFpHVnVkR2xtZVNJc0ltbHpjM1ZsSWwxOS5BY1N2T3hXTHVvekp4c1FqRzFEQzNTSzhGNnFnR2VOQWVwa1lDRnlUaitxQWZ5RzFiaVFJSit4RkVEUEl3cnlndHZOVDFXRnduUVlPQ3dkMEdjdElpUXc.AU+ZZhSO5SSrbHbMx9gby4biP/+4d+4wjWwFoyk8GtRY5PwQcVwyKdyeLiLPZjNk/LV+g1Jfso3eJSUowEJRFwQ";
            Identity identity = Identity.FromString(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual(new Guid("77c36067-0aa6-404e-860c-3a611d8d7cd7"), identity.UID);
            Assert.AreEqual(new Guid("8d512923-8727-4276-b939-95b5bdb0ec7c"), identity.SubjectId);
            Assert.AreEqual(1626214237, identity.IssuedAt);
            Assert.AreEqual(1657750237, identity.ExpiresAt);
            Assert.AreEqual(new Guid("037d9135-f6ea-45e1-9aa6-a6d47176e00d"), identity.IssuerId);
            Assert.AreEqual("CYHt84GVwnFqkmYRM4spiC7CbWsczAc5bCKjYWpKcXP9yGxG9DxAym", identity.PublicKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            identity.VerifyTrust();
        }

    }

}
