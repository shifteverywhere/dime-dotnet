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
            Guid subjectId = Guid.NewGuid();
            Key key = Key.Generate(KeyType.Identity, -1);            
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Issue };
            Identity identity = IdentityIssuingRequest.Generate(key, caps).SelfIssue(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 10, key, Commons.SYSTEM_NAME);
            //string k = key.Export();
            //string i = identity.Export();
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
            Key key = Key.Generate(KeyType.Identity, -1);
            List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify };
            //List<Capability> caps = new List<Capability> { Capability.Generic, Capability.Identify, Capability.Issue };
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(key, caps);
            Identity identity = iir.Issue(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, caps, null);
            //Identity identity = iir.Issue(subjectId, IdentityIssuingRequest.VALID_FOR_1_YEAR * 5, Commons.TrustedKey, Commons.TrustedIdentity, caps, null);
            //string k = key.Export();
            //string i = identity.Export();
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
                Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), reqCaps).Issue(Guid.NewGuid(), 100, Commons.TrustedKey, Commons.TrustedIdentity, allowCaps, null);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Key key = Key.Generate(KeyType.Identity);
            List<Capability> caps = new List<Capability> { Capability.Issue, Capability.Generic };
            Identity identity = IdentityIssuingRequest.Generate(key, caps).Issue(Guid.NewGuid(), 100, Commons.TrustedKey, Commons.TrustedIdentity, caps, null);
            Assert.IsTrue(identity.HasCapability(Capability.Issue));
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
        }

       [TestMethod]
        public void IssueTest5()
        {
            Identity.SetTrustedIdentity(null);
            List<Capability> caps = new List<Capability> { Capability.Issue };
            try {
                Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), caps).Issue(Guid.NewGuid(), 100, Commons.TrustedKey, null, caps, null);
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
            Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity)).Issue(Guid.NewGuid(), 100, Commons.IntermediateKey, Commons.IntermediateIdentity, caps, null);
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
            Identity identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity)).Issue(Guid.NewGuid(), 100, Commons.IntermediateKey, Commons.IntermediateIdentity, caps, null);
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
            Key key = Crypto.GenerateKey(KeyType.Identity);
            Identity identity = IdentityIssuingRequest.Generate(key, caps).Issue(Guid.NewGuid(), IdentityIssuingRequest.VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, caps, null);
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
            string exported = "Di:ID.eyJzeXMiOiJkaW1lIiwidWlkIjoiY2FiOTgxNmYtYWYzZi00Yjg0LTlmNzktZGNlNWU2M2U5MzI2Iiwic3ViIjoiNmRlZTVlOTEtOTJhOS00ZGVjLWI5ZjgtMWNlZTc0NjBiODY3IiwiaXNzIjoiNTk4NjZjYWQtMTU1MS00NGM5LWJiNjMtMDAyNmU3ODJjMGZmIiwiaWF0IjoiMjAyMS0xMi0wMVQyMToxMDowOS45MTQ5MTVaIiwiZXhwIjoiMjAyMi0xMi0wMVQyMToxMDowOS45MTQ5MTVaIiwicHViIjoiMlREWGRvTnZOWno2clZzN21hMjdtSjhCUmdBblY2UHB3U25EZmpBQVpkR3JlNzExQzIxcVRhNWRhIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.SUQuZXlKemVYTWlPaUprYVcxbElpd2lkV2xrSWpvaU1qWTVZVFF6TURJdE1tWm1aaTAwTjJKbExXSTFabVl0TkRGa01XSTFNbU0wTlRneUlpd2ljM1ZpSWpvaU5UazROalpqWVdRdE1UVTFNUzAwTkdNNUxXSmlOak10TURBeU5tVTNPREpqTUdabUlpd2lhWE56SWpvaVlUTmtZV1poWXpZdFlqRXdPUzAwT1dReUxXRmhaR0V0Tkdaa01ERTBZalZsTlRabUlpd2lhV0YwSWpvaU1qQXlNUzB4TWkwd01WUXlNRG8xT0Rvd01DNHdOVFkyTXpKYUlpd2laWGh3SWpvaU1qQXlOaTB4TVMwek1GUXlNRG8xT0Rvd01DNHdOVFkyTXpKYUlpd2ljSFZpSWpvaU1sUkVXR1J2VG5aS1MxWTJTRGw1WlVjell6STNhMDQ1UVV4UWRIQTVOblZMYWxGRVNsSm5WRUp2V21kMlVWTlpZVVJ2YTFOdk5IQlhJaXdpWTJGd0lqcGJJbWRsYm1WeWFXTWlMQ0pwWkdWdWRHbG1lU0lzSW1semMzVmxJbDE5Lkp1N3hwTHg1R1dlN3dIb3doK0phOWl3bDNsb0Vob1JUR0RNTUJINFNjMUhYQWp1N1FvUXk5THlSOEIxV3lSOTBFczVmajhKa2E2T0UvSzRzN25Fb0NB.KkBWZ9oMkIUAln6xXOYeEgLa0iyUkw5omv1644tVWDlZ8NVpNTAdPmm8RrYoHix7vCWZPzmhsrCYJCl8zpdnBA";
            Identity identity = Item.Import<Identity>(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual(Commons.SYSTEM_NAME, identity.SystemName);
            Assert.AreEqual(new Guid("cab9816f-af3f-4b84-9f79-dce5e63e9326"), identity.UniqueId);
            Assert.AreEqual(new Guid("6dee5e91-92a9-4dec-b9f8-1cee7460b867"), identity.SubjectId);
            Assert.AreEqual(DateTime.Parse("2021-12-01T21:10:09.914915Z").ToUniversalTime(), identity.IssuedAt);
            Assert.AreEqual(DateTime.Parse("2022-12-01T21:10:09.914915Z").ToUniversalTime(), identity.ExpiresAt);
            Assert.AreEqual(Commons.IntermediateIdentity.SubjectId, identity.IssuerId);
            Assert.AreEqual("2TDXdoNvNZz6rVs7ma27mJ8BRgAnV6PpwSnDfjAAZdGre711C21qTa5da", identity.PublicKey);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            identity.VerifyTrust();
        }

        [TestMethod]
        public void ambitTest1() {
            List<string> ambits = new List<string>() { "global", "administrator" };
            Key key = Key.Generate(KeyType.Identity);
            
            Identity identity1 = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100, key, Commons.SYSTEM_NAME, ambits, null);
            Assert.AreEqual(2, identity1.Ambits.Count);
            Assert.IsTrue(identity1.HasAmbit(ambits[0]));
            Assert.IsTrue(identity1.HasAmbit(ambits[1]));

            Identity identity2 = Item.Import<Identity>(identity1.Export());
            Assert.AreEqual(2, identity2.Ambits.Count);
            Assert.IsTrue(identity2.HasAmbit(ambits[0]));
            Assert.IsTrue(identity2.HasAmbit(ambits[1]));
        }

        [TestMethod]
        public void methodsTest1() {
            List<string> methods = new List<string> { "dime", "sov" };
            Key key = Key.Generate(KeyType.Identity);

            Identity identity1 = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100, key, Commons.SYSTEM_NAME, null, methods);
            Assert.IsNotNull(identity1.Methods);
            Assert.AreEqual(2, identity1.Methods.Count);
            Assert.IsTrue(identity1.Methods.Contains(methods[0]));
            Assert.IsTrue(identity1.Methods.Contains(methods[1]));

            Identity identity2 = Item.Import<Identity>(identity1.Export());
            Assert.IsNotNull(identity2.Methods);
            Assert.AreEqual(2, identity2.Methods.Count);
            Assert.IsTrue(identity2.Methods.Contains(methods[0]));
            Assert.IsTrue(identity2.Methods.Contains(methods[1]));
        }

        [TestMethod]
        public void principlesTest1() {
            Key key = Key.Generate(KeyType.Identity);
            Dictionary<string, dynamic> principles = new Dictionary<string, dynamic>();
            principles["tag"] = "Racecar is racecar backwards.";
            principles["nbr"] = new String[] { "one" , "two", "three" };
            Identity identity =  IdentityIssuingRequest.Generate(key, new List<Capability>() { Capability.Generic }, principles).SelfIssue(Guid.NewGuid(), 100, key, Commons.SYSTEM_NAME);
            Assert.AreEqual("Racecar is racecar backwards.", identity.Principles["tag"]);
            string[] nbr = (string[])identity.Principles["nbr"];
            Assert.AreEqual(3, nbr.Length);
            Assert.AreEqual("two", nbr[1]);
        }

        [TestMethod]
        public void principlesTest2() {
            Key key = Key.Generate(KeyType.Identity);
            Dictionary<string, dynamic> principles = new Dictionary<string, dynamic>();
            principles["tag"] = "Racecar is racecar backwards.";
            principles["nbr"] = new String[] { "one" , "two", "three" };
            Identity identity1 =  IdentityIssuingRequest.Generate(key, new List<Capability>() { Capability.Generic }, principles).SelfIssue(Guid.NewGuid(), 100, key, Commons.SYSTEM_NAME);
            Identity identity2 = Item.Import<Identity>(identity1.Export());
            string str = (String)identity2.Principles["tag"];
            Assert.AreEqual("Racecar is racecar backwards.", identity2.Principles["tag"]);
            object[] nbr = (object[])identity2.Principles["nbr"];
            Assert.AreEqual(3, nbr.Length);
            Assert.AreEqual("three", nbr[2]);
        }

    }

}
