//
//  IdentityTests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using DiME;

namespace DiME_test
{
    [TestClass]
    public class IdentityTests
    {

        [TestMethod]
        public void IssueTest1()
        {
            Identity.SetTrustedIdentity(null);
            var subjectId = Guid.NewGuid();
            var key = Key.Generate(KeyType.Identity);            
            var caps = new List<Capability> { Capability.Generic, Capability.Issue };
            var identity = IdentityIssuingRequest.Generate(key, caps).SelfIssue(subjectId, IdentityIssuingRequest._VALID_FOR_1_YEAR * 10, key, Commons._SYSTEM_NAME);
            Assert.AreEqual(Commons._SYSTEM_NAME, identity.SystemName);
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(subjectId == identity.IssuerId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(identity.HasCapability(caps[1]));
            Assert.IsTrue(identity.HasCapability(Capability.Self));
            Assert.AreEqual(key.Public, identity.PublicKey.Public);
            Assert.IsNotNull(identity.IssuedAt);
            Assert.IsNotNull(identity.ExpiresAt);
            Assert.IsTrue(identity.IssuedAt < identity.ExpiresAt);
            Assert.IsTrue(subjectId == identity.IssuerId);
        }

        [TestMethod]
        public void IssueTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            var subjectId = Guid.NewGuid();
            var key = Key.Generate(KeyType.Identity);
            var caps = new List<Capability> { Capability.Generic, Capability.Identify };
            var iir = IdentityIssuingRequest.Generate(key, caps);
            var identity = iir.Issue(subjectId, IdentityIssuingRequest._VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            Assert.AreEqual(Identity.TrustedIdentity.SystemName, identity.SystemName);
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(identity.HasCapability(caps[1]));
            Assert.AreEqual(key.Public, identity.PublicKey.Public);
            Assert.IsNotNull(identity.IssuedAt);
            Assert.IsNotNull(identity.ExpiresAt);
            Assert.IsTrue(identity.IssuedAt < identity.ExpiresAt);
            Assert.IsTrue(Commons.IntermediateIdentity.SubjectId == identity.IssuerId);
        }

       [TestMethod]
        public void IssueTest3()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            var reqCaps = new List<Capability> { Capability.Issue };
            var allowCaps = new List<Capability> { Capability.Generic, Capability.Identify };
            try {
                _ = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), reqCaps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, true, allowCaps);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            var key = Key.Generate(KeyType.Identity);
            var caps = new List<Capability> { Capability.Issue, Capability.Generic };
            var identity = IdentityIssuingRequest.Generate(key, caps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, true, caps);
            Assert.IsTrue(identity.HasCapability(Capability.Issue));
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
        }

       [TestMethod]
        public void IssueTest5()
        {
            Identity.SetTrustedIdentity(null);
            var caps = new List<Capability> { Capability.Issue };
            try {
                _ = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), caps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, null, true, caps);
            } catch (ArgumentNullException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSelfSignedTest1()
        {
            Identity.SetTrustedIdentity(null);
            var key = Key.Generate(KeyType.Identity);
            var identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons._SYSTEM_NAME);
            Assert.IsTrue(identity.IsSelfSigned);
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            var caps = new List<Capability> { Capability.Generic };
            var identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity)).Issue(Guid.NewGuid(), 100L, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            Assert.IsFalse(identity.IsSelfSigned);
        }

        [TestMethod]
        public void IsTrustedTest1()
        {
            try {
                Identity.SetTrustedIdentity(null);
                var key = Key.Generate(KeyType.Identity);
                var identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons._SYSTEM_NAME);
                Assert.IsTrue(identity.IsSelfSigned);
                identity.IsTrusted();
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void IsTrustedTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            var caps = new List<Capability> { Capability.Generic };
            var identity = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity)).Issue(Guid.NewGuid(), 100L, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            Assert.IsTrue(identity.IsTrusted());
        }

        [TestMethod]
        public void IsTrustedTest3()
        {
            Identity.SetTrustedIdentity(null);
            var key = Key.Generate(KeyType.Identity);
            var identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons._SYSTEM_NAME);
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Assert.IsFalse(identity.IsTrusted());
        }

        [TestMethod]
        public void IsTrustedTest4()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Assert.IsTrue(Commons.IntermediateIdentity.IsTrusted());
        }
        
        [TestMethod]
        public void IsTrustedTest5()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Assert.IsTrue(Commons.AudienceIdentity.IsTrusted());
        }
        
        [TestMethod]
        public void IsTrustedTest6()
        {
            Identity.SetTrustedIdentity(null);
            Assert.IsTrue(Commons.AudienceIdentity.IsTrusted(Commons.IntermediateIdentity));
        }
        
        [TestMethod]
        public void IsTrustedTest7()
        {
            Identity.SetTrustedIdentity(null);
            Assert.IsFalse(Commons.AudienceIdentity.IsTrusted(Commons.IssuerIdentity));
        }
        
        [TestMethod]
        public void IsTrustedTest8() {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            var nodeCaps = new List<Capability> { Capability.Generic, Capability.Issue };
            var key1 = Key.Generate(KeyType.Identity);
            var node1 = IdentityIssuingRequest.Generate(key1, nodeCaps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, true, nodeCaps, nodeCaps);
            var key2 = Key.Generate(KeyType.Identity);
            var node2 = IdentityIssuingRequest.Generate(key2, nodeCaps).Issue(Guid.NewGuid(), 100L, key1, node1, true, nodeCaps, nodeCaps);
            var key3 = Key.Generate(KeyType.Identity);
            var node3 = IdentityIssuingRequest.Generate(key3, nodeCaps).Issue(Guid.NewGuid(), 100L, key2, node2, true, nodeCaps, nodeCaps);
            var leafCaps = new List<Capability> { Capability.Generic };
            var leaf = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), leafCaps).Issue(Guid.NewGuid(), 100L, key3, node3, true, leafCaps, leafCaps);
            Assert.IsTrue(leaf.IsTrusted());
            Assert.IsTrue(leaf.IsTrusted(node1));
            Assert.IsTrue(leaf.IsTrusted(node2));
            Assert.IsTrue(leaf.IsTrusted(node3));
            Assert.IsFalse(leaf.IsTrusted(Commons.IntermediateIdentity));
        }
        
        [TestMethod]
        public void IsTrustedTest9() {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            var nodeCaps = new List<Capability> { Capability.Generic, Capability.Issue };
            var key1 = Key.Generate(KeyType.Identity);
            var node1 = IdentityIssuingRequest.Generate(key1, nodeCaps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, false, nodeCaps, nodeCaps);
            var key2 = Key.Generate(KeyType.Identity);
            var node2 = IdentityIssuingRequest.Generate(key2, nodeCaps).Issue(Guid.NewGuid(), 100L, key1, node1, false, nodeCaps, nodeCaps);
            var leafCaps = new List<Capability> { Capability.Generic };
            var leaf = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity), leafCaps).Issue(Guid.NewGuid(), 100L, key2, node2, false, leafCaps, leafCaps);
            Assert.IsFalse(leaf.IsTrusted());
            Assert.IsFalse(leaf.IsTrusted(node1));
            Assert.IsTrue(leaf.IsTrusted(node2));
            Assert.IsFalse(leaf.IsTrusted(Commons.IntermediateIdentity));
        }

        [TestMethod]
        public void ExportTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            var caps = new List<Capability> { Capability.Generic, Capability.Identify };
            var key = Crypto.GenerateKey(KeyType.Identity);
            var identity = IdentityIssuingRequest.Generate(key, caps).Issue(Guid.NewGuid(), IdentityIssuingRequest._VALID_FOR_1_YEAR, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            var exported = identity.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith($"{Envelope._HEADER}:{Identity._TAG}"));
            Assert.AreEqual(4, exported.Split(new[] { '.' }).Length);
        }

        [TestMethod]
        public void ImportTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            const string exported = "Di:ID.eyJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJ1aWQiOiIxNDRiMDZkZS1jM2U5LTRjMTYtYmZiZS00NjAxMTc2YzhkYzYiLCJzdWIiOiIzZGVjZjlkNC1kNDM0LTRlNTQtYmI3Mi00NzY3Nzg0ZDgwMzAiLCJpc3MiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpYXQiOiIyMDIxLTEyLTAyVDIyOjMxOjQwLjI1Njk4OFoiLCJleHAiOiIyMDIyLTEyLTAyVDIyOjMxOjQwLjI1Njk4OFoiLCJwdWIiOiIyVERYZG9OdmlSNFJlTVR6OEFEUTM2NVhGRkh2amNLOWp1dGF5bTNnM2VZeWJSTDhZYXgxWENTY1kiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKemVYTWlPaUprYVcxbExXUnZkRzVsZEMxeVpXWWlMQ0oxYVdRaU9pSTNNV1k1TkdGa055MDNaakF6TFRRMk5EVXRPVEl3WWkwd1pEaGtPV0V5WVRGa01XSWlMQ0p6ZFdJaU9pSmxPRFE1WVdRNU9TMDVZV000TFRRMlpUa3RZalV5TlMxbFpXTmlNV0V3TmpFM05EVWlMQ0pwYzNNaU9pSTRNVGN4TjJWa09DMDNOMkZsTFRRMk16TXRZVEE1WVMwMllXTTFaRGswWldZeU9HUWlMQ0pwWVhRaU9pSXlNREl4TFRFeUxUQXlWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0psZUhBaU9pSXlNREkyTFRFeUxUQXhWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0p3ZFdJaU9pSXlWRVJZWkc5T2RsWnpSMVpJT0VNNVZWcDFaSEJpUW5aV1Uwc3hSbVZwTlhJMFdWUmFUWGhoUW1GNmIzTnZNbkJNY0ZCWFZFMW1ZMDRpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLjc5SjlldTNxZXJqMW4xdEpSaUJQenNURHNBNWlqWG41REs3ZlVuNEpRcmhzZUJXN0lrYWRBekNFRGtQcktoUG1lMGtzanVhMjhUQitVTGh4bGEybkNB.mlVe0Wj6H3vlVjc4rrhzqSEGwLY4w6FrLrL8kDagEx+bmRsTwlheUJtQY0TDPlqIFL62ZQxsbdFbUDKyXDq7Dw";
            var identity = Item.Import<Identity>(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual(Commons._SYSTEM_NAME, identity.SystemName);
            Assert.AreEqual(new Guid("144b06de-c3e9-4c16-bfbe-4601176c8dc6"), identity.UniqueId);
            Assert.AreEqual(new Guid("3decf9d4-d434-4e54-bb72-4767784d8030"), identity.SubjectId);
            Assert.AreEqual(DateTime.Parse("2021-12-02T22:31:40.256988Z").ToUniversalTime(), identity.IssuedAt);
            Assert.AreEqual(DateTime.Parse("2022-12-02T22:31:40.256988Z").ToUniversalTime(), identity.ExpiresAt);
            Assert.AreEqual(Commons.IntermediateIdentity.SubjectId, identity.IssuerId);
            Assert.AreEqual("2TDXdoNviR4ReMTz8ADQ365XFFHvjcK9jutaym3g3eYybRL8Yax1XCScY", identity.PublicKey.Public);
            Assert.IsTrue(identity.HasCapability(Capability.Generic));
            Assert.IsTrue(identity.HasCapability(Capability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            Assert.IsTrue(identity.IsTrusted());
        }

        [TestMethod]
        public void AmbitTest1() {
            var ambits = new List<string>() { "global", "administrator" };
            var key = Key.Generate(KeyType.Identity);
            
            var identity1 = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100, key, Commons._SYSTEM_NAME, ambits);
            Assert.AreEqual(2, identity1.Ambits.Count);
            Assert.IsTrue(identity1.HasAmbit(ambits[0]));
            Assert.IsTrue(identity1.HasAmbit(ambits[1]));

            var identity2 = Item.Import<Identity>(identity1.Export());
            Assert.AreEqual(2, identity2.Ambits.Count);
            Assert.IsTrue(identity2.HasAmbit(ambits[0]));
            Assert.IsTrue(identity2.HasAmbit(ambits[1]));
        }

        [TestMethod]
        public void MethodsTest1() {
            var methods = new List<string> { "dime", "sov" };
            var key = Key.Generate(KeyType.Identity);

            var identity1 = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons._SYSTEM_NAME, null, methods);
            Assert.IsNotNull(identity1.Methods);
            Assert.AreEqual(2, identity1.Methods.Count);
            Assert.IsTrue(identity1.Methods.Contains(methods[0]));
            Assert.IsTrue(identity1.Methods.Contains(methods[1]));

            var identity2 = Item.Import<Identity>(identity1.Export());
            Assert.IsNotNull(identity2.Methods);
            Assert.AreEqual(2, identity2.Methods.Count);
            Assert.IsTrue(identity2.Methods.Contains(methods[0]));
            Assert.IsTrue(identity2.Methods.Contains(methods[1]));
        }

        [TestMethod]
        public void PrinciplesTest1() {
            var key = Key.Generate(KeyType.Identity);
            var principles = new Dictionary<string, dynamic>
            {
                ["tag"] = "Racecar is racecar backwards.",
                ["nbr"] = new[] { "one" , "two", "three" }
            };
            var identity =  IdentityIssuingRequest.Generate(key, new List<Capability>() { Capability.Generic }, principles).SelfIssue(Guid.NewGuid(), 100L, key, Commons._SYSTEM_NAME);
            Assert.AreEqual("Racecar is racecar backwards.", identity.Principles["tag"]);
            var nbr = (string[])identity.Principles["nbr"];
            Assert.AreEqual(3, nbr.Length);
            Assert.AreEqual("two", nbr[1]);
        }

        [TestMethod]
        public void PrinciplesTest2() {
            var key = Key.Generate(KeyType.Identity);
            var principles = new Dictionary<string, dynamic>
            {
                ["tag"] = "Racecar is racecar backwards.",
                ["nbr"] = new[] { "one" , "two", "three" }
            };
            var identity1 =  IdentityIssuingRequest.Generate(key, new List<Capability>() { Capability.Generic }, principles).SelfIssue(Guid.NewGuid(), 100L, key, Commons._SYSTEM_NAME);
            var identity2 = Item.Import<Identity>(identity1.Export());
            Assert.AreEqual("Racecar is racecar backwards.", identity2.Principles["tag"]);
            var nbr = (object[])identity2.Principles["nbr"];
            Assert.AreEqual(3, nbr.Length);
            Assert.AreEqual("three", nbr[2]);
        }

    }

}
