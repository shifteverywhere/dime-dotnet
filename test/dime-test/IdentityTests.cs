//
//  IdentityTests.cs
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using DiME;

namespace DiME_test
{
    [TestClass]
    public class IdentityTests
    {

        [TestMethod]
        public void IssueTest1()
        {
            Dime.TrustedIdentity = null;
            var subjectId = Guid.NewGuid();
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);            
            var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
            var identity = IdentityIssuingRequest.Generate(key, caps).SelfIssue(subjectId, Dime.ValidFor1Year * 10, key, Commons.SystemName);
            Assert.AreEqual(Commons.SystemName, identity.SystemName);
            Assert.IsTrue(subjectId == identity.SubjectId);
            Assert.IsTrue(subjectId == identity.IssuerId);
            Assert.IsTrue(identity.HasCapability(caps[0]));
            Assert.IsTrue(identity.HasCapability(caps[1]));
            Assert.IsTrue(identity.HasCapability(IdentityCapability.Self));
            Assert.AreEqual(key.Public, identity.PublicKey.Public);
            Assert.IsNotNull(identity.IssuedAt);
            Assert.IsNotNull(identity.ExpiresAt);
            Assert.IsTrue(identity.IssuedAt < identity.ExpiresAt);
            Assert.IsTrue(subjectId == identity.IssuerId);
        }

        [TestMethod]
        public void IssueTest2()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var subjectId = Guid.NewGuid();
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Identify };
            var iir = IdentityIssuingRequest.Generate(key, caps);
            var identity = iir.Issue(subjectId, Dime.ValidFor1Year, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            Assert.AreEqual(Dime.TrustedIdentity.SystemName, identity.SystemName);
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
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var reqCaps = new List<IdentityCapability> { IdentityCapability.Issue };
            var allowCaps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Identify };
            try {
                _ = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), reqCaps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, true, allowCaps);
            } catch (IdentityCapabilityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IssueTest4()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var caps = new List<IdentityCapability> { IdentityCapability.Issue, IdentityCapability.Generic };
            var identity = IdentityIssuingRequest.Generate(key, caps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, true, caps);
            Assert.IsTrue(identity.HasCapability(IdentityCapability.Issue));
            Assert.IsTrue(identity.HasCapability(IdentityCapability.Generic));
        }

       [TestMethod]
        public void IssueTest5()
        {
            Dime.TrustedIdentity = null;
            var caps = new List<IdentityCapability> { IdentityCapability.Issue };
            try {
                _ = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), caps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, null, true, caps);
            } catch (ArgumentNullException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSelfSignedTest1()
        {
            Dime.TrustedIdentity = null;
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons.SystemName);
            Assert.IsTrue(identity.IsSelfSigned);
        }

        [TestMethod]
        public void IsSelfSignedTest2()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var caps = new List<IdentityCapability> { IdentityCapability.Generic };
            var identity = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null)).Issue(Guid.NewGuid(), 100L, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            Assert.IsFalse(identity.IsSelfSigned);
        }

        [TestMethod]
        public void IsTrustedTest1()
        {
            try {
                Dime.TrustedIdentity = null;
                var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
                var identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons.SystemName);
                Assert.IsTrue(identity.IsSelfSigned);
                identity.IsTrusted();
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "This should not happen.");
        }

        [TestMethod]
        public void IsTrustedTest2()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var caps = new List<IdentityCapability> { IdentityCapability.Generic };
            var identity = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null)).Issue(Guid.NewGuid(), 100L, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            Assert.IsTrue(identity.IsTrusted());
        }

        [TestMethod]
        public void IsTrustedTest3()
        {
            Dime.TrustedIdentity = null;
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons.SystemName);
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            Assert.IsFalse(identity.IsTrusted());
        }

        [TestMethod]
        public void IsTrustedTest4()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            Assert.IsTrue(Commons.IntermediateIdentity.IsTrusted());
        }
        
        [TestMethod]
        public void IsTrustedTest5()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            Assert.IsTrue(Commons.AudienceIdentity.IsTrusted());
        }
        
        [TestMethod]
        public void IsTrustedTest6()
        {
            Dime.TrustedIdentity = null;
            Assert.IsTrue(Commons.AudienceIdentity.IsTrusted(Commons.IntermediateIdentity));
        }
        
        [TestMethod]
        public void IsTrustedTest7()
        {
            Dime.TrustedIdentity = null;
            Assert.IsFalse(Commons.AudienceIdentity.IsTrusted(Commons.IssuerIdentity));
        }
        
        [TestMethod]
        public void IsTrustedTest8() {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var nodeCaps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
            var key1 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var node1 = IdentityIssuingRequest.Generate(key1, nodeCaps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, true, nodeCaps, nodeCaps);
            var key2 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var node2 = IdentityIssuingRequest.Generate(key2, nodeCaps).Issue(Guid.NewGuid(), 100L, key1, node1, true, nodeCaps, nodeCaps);
            var key3 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var node3 = IdentityIssuingRequest.Generate(key3, nodeCaps).Issue(Guid.NewGuid(), 100L, key2, node2, true, nodeCaps, nodeCaps);
            var leafCaps = new List<IdentityCapability> { IdentityCapability.Generic };
            var leaf = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), leafCaps).Issue(Guid.NewGuid(), 100L, key3, node3, true, leafCaps, leafCaps);
            Assert.IsTrue(leaf.IsTrusted());
            Assert.IsTrue(leaf.IsTrusted(node1));
            Assert.IsTrue(leaf.IsTrusted(node2));
            Assert.IsTrue(leaf.IsTrusted(node3));
            Assert.IsFalse(leaf.IsTrusted(Commons.IntermediateIdentity));
        }
        
        [TestMethod]
        public void IsTrustedTest9() {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var nodeCaps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
            var key1 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var node1 = IdentityIssuingRequest.Generate(key1, nodeCaps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, false, nodeCaps, nodeCaps);
            var key2 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var node2 = IdentityIssuingRequest.Generate(key2, nodeCaps).Issue(Guid.NewGuid(), 100L, key1, node1, false, nodeCaps, nodeCaps);
            var leafCaps = new List<IdentityCapability> { IdentityCapability.Generic };
            var leaf = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), leafCaps).Issue(Guid.NewGuid(), 100L, key2, node2, false, leafCaps, leafCaps);
            Assert.IsFalse(leaf.IsTrusted());
            Assert.IsFalse(leaf.IsTrusted(node1));
            Assert.IsTrue(leaf.IsTrusted(node2));
            Assert.IsFalse(leaf.IsTrusted(Commons.IntermediateIdentity));
        }

        [TestMethod]
        public void ExportTest1()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Identify };
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var identity = IdentityIssuingRequest.Generate(key, caps).Issue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
            var exported = identity.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith($"{Envelope.Header}:{Identity.ItemIdentifier}"));
            Assert.AreEqual(4, exported.Split(new[] { '.' }).Length);
        }

        [TestMethod]
        public void ImportTest1()
        {
            Dime.TrustedIdentity = Commons.TrustedIdentity;
            const string exported = "Di:ID.eyJ1aWQiOiI0YTY5Zjg4Ni1hN2JhLTQ5NGEtYTdiYy1mZGMyYmM4YWQ3MmYiLCJzeXMiOiJkaW1lLWRvdG5ldC1yZWYiLCJzdWIiOiI2MGEzZmE5ZS0wODI5LTQxMjAtODVhYS0zMjE2MTU2MDA1ZTUiLCJpc3MiOiJlODQ5YWQ5OS05YWM4LTQ2ZTktYjUyNS1lZWNiMWEwNjE3NDUiLCJpYXQiOiIyMDIyLTA5LTE0VDIwOjI0OjQ4LjEzODQ5MVoiLCJleHAiOiIyMDIzLTA5LTE0VDIwOjI0OjQ4LjEzODQ5MVoiLCJwdWIiOiIyVERYZG9OdWVhc2REYUh1NEZueHhnUUZleDk0czI3eGpBMnNTeE5BeUU1cEd1V0FpWUczMzd4ZEciLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sInByaSI6bnVsbH0.SUQuZXlKemVYTWlPaUprYVcxbExXUnZkRzVsZEMxeVpXWWlMQ0oxYVdRaU9pSTNNV1k1TkdGa055MDNaakF6TFRRMk5EVXRPVEl3WWkwd1pEaGtPV0V5WVRGa01XSWlMQ0p6ZFdJaU9pSmxPRFE1WVdRNU9TMDVZV000TFRRMlpUa3RZalV5TlMxbFpXTmlNV0V3TmpFM05EVWlMQ0pwYzNNaU9pSTRNVGN4TjJWa09DMDNOMkZsTFRRMk16TXRZVEE1WVMwMllXTTFaRGswWldZeU9HUWlMQ0pwWVhRaU9pSXlNREl4TFRFeUxUQXlWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0psZUhBaU9pSXlNREkyTFRFeUxUQXhWREl5T2pJMU9qQTRMakE0TnpNeU1Wb2lMQ0p3ZFdJaU9pSXlWRVJZWkc5T2RsWnpSMVpJT0VNNVZWcDFaSEJpUW5aV1Uwc3hSbVZwTlhJMFdWUmFUWGhoUW1GNmIzTnZNbkJNY0ZCWFZFMW1ZMDRpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLjc5SjlldTNxZXJqMW4xdEpSaUJQenNURHNBNWlqWG41REs3ZlVuNEpRcmhzZUJXN0lrYWRBekNFRGtQcktoUG1lMGtzanVhMjhUQitVTGh4bGEybkNB.kOkZXrN1DXY+asOrkeAhyLRqryQZVSt3s4ybdiS8UAsF/hFDACpI2T8BN2RqIPWHozSPkvZaPwlacAovMOuMBw";
            var identity = Item.Import<Identity>(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual("dime-dotnet-ref", identity.SystemName);
            Assert.AreEqual(new Guid("4a69f886-a7ba-494a-a7bc-fdc2bc8ad72f"), identity.UniqueId);
            Assert.AreEqual(new Guid("60a3fa9e-0829-4120-85aa-3216156005e5"), identity.SubjectId);
            Assert.AreEqual(DateTime.Parse("2022-09-14T20:24:48.138491Z").ToUniversalTime(), identity.IssuedAt);
            Assert.AreEqual(DateTime.Parse("2023-09-14T20:24:48.138491Z").ToUniversalTime(), identity.ExpiresAt);
            Assert.AreEqual(Commons.IntermediateIdentity.SubjectId, identity.IssuerId);
            Assert.AreEqual("2TDXdoNueasdDaHu4FnxxgQFex94s27xjA2sSxNAyE5pGuWAiYG337xdG", identity.PublicKey.Public);
            Assert.IsTrue(identity.HasCapability(IdentityCapability.Generic));
            Assert.IsTrue(identity.HasCapability(IdentityCapability.Identify));
            Assert.IsNotNull(identity.TrustChain);
            Assert.IsTrue(identity.IsTrusted());
        }

        [TestMethod]
        public void AmbitTest1() {
            var ambitList = new List<string>() { "global", "administrator" };
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            
            var identity1 = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100, key, Commons.SystemName, ambitList);
            Assert.AreEqual(2, identity1.AmbitList.Count);
            Assert.IsTrue(identity1.HasAmbit(ambitList[0]));
            Assert.IsTrue(identity1.HasAmbit(ambitList[1]));

            var identity2 = Item.Import<Identity>(identity1.Export());
            Assert.AreEqual(2, identity2.AmbitList.Count);
            Assert.IsTrue(identity2.HasAmbit(ambitList[0]));
            Assert.IsTrue(identity2.HasAmbit(ambitList[1]));
        }

        [TestMethod]
        public void MethodsTest1() {
            var methods = new List<string> { "dime", "sov" };
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);

            var identity1 = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons.SystemName, null, methods);
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
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var principles = new Dictionary<string, dynamic>
            {
                ["tag"] = Commons.Payload,
                ["nbr"] = new[] { "one" , "two", "three" }
            };
            var identity = IdentityIssuingRequest.Generate(key, new List<IdentityCapability>() { IdentityCapability.Generic }, principles).SelfIssue(Guid.NewGuid(), 100L, key, Commons.SystemName);
            Assert.AreEqual( Commons.Payload, identity.Principles["tag"]);
            var nbr = (string[])identity.Principles["nbr"]; // This identity if not exported, string[] is expected
            Assert.AreEqual(3, nbr.Length);
            Assert.AreEqual("two", nbr[1]);
        }

        [TestMethod]
        public void PrinciplesTest2() {
            var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            var principles = new Dictionary<string, dynamic>
            {
                ["tag"] =  Commons.Payload,
                ["nbr"] = new[] { "one" , "two", "three" }
            };
            var identity1 =  IdentityIssuingRequest.Generate(key, new List<IdentityCapability>() { IdentityCapability.Generic }, principles).SelfIssue(Guid.NewGuid(), 100L, key, Commons.SystemName);
            var identity2 = Item.Import<Identity>(identity1.Export());
            Assert.AreEqual( Commons.Payload, identity2.Principles["tag"]);
            var nbr = (List<string>) identity2.Principles["nbr"]; 
            Assert.AreEqual(3, nbr.Count);
            Assert.AreEqual("three", nbr[2]);
        }

        [TestMethod]
        public void AlienImportTest1()
        {
            const string exported =
                "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyJdLCJleHAiOiIyMDIzLTA3LTAxVDEwOjAwOjEzLjYzNjk3NloiLCJpYXQiOiIyMDIyLTA3LTAxVDEwOjAwOjEzLjYzNjk3NloiLCJpc3MiOiIyY2JmZmRlMS05ZjNkLTRmMzgtOTM5Yi0yZTFmZTc0OGQ4ZGMiLCJwdWIiOiIyVERYZG9OdVFpQ0o4YWdLckJtRnFNWEF2ZUxBWWNLUVNrY0ZVUkpWSGhvVlB2UkR5M2dNS0xLdnQiLCJzdWIiOiJkMDEwOTZiMS05YzBiLTQ5Y2UtYmY5OC1mNDIwZjVhMGVkNjIiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6IjA4NDA2ZDBlLTdhZmEtNDRlZC1iZTU5LThhNGIwZDBkMzQ3NiJ9.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHdOaTB5T0ZReU1EbzFOam93Tnk0d09EZ3hOakZhSWl3aWFXRjBJam9pTWpBeU1pMHdOaTB5T1ZReU1EbzFOam93Tnk0d09EZ3hOakZhSWl3aWFYTnpJam9pTTJNek5tWTRZbVF0TWpsallTMDBObVV3TFRobU5EWXRZMkpqWXpnNFpqRm1NVEZrSWl3aWNIVmlJam9pUkZOVVRpNHlObVV6VUhkU1NIbElXbkJMYUdSYU5GWk1abG8zUmxGalJrMDBhMHg1UkUwMU9EWmlUbWxWYjFSVE4yNXJXalJIY3lJc0luTjFZaUk2SWpKalltWm1aR1V4TFRsbU0yUXROR1l6T0MwNU16bGlMVEpsTVdabE56UTRaRGhrWXlJc0luTjVjeUk2SW1sdkxtUnBiV1ZtYjNKdFlYUXVjbVZtSWl3aWRXbGtJam9pT1Rnd09HSmtZelV0Wm1JM05pMDBNelZsTFdJMU1EVXRNelZqTnpaaVpUYzROemsxSW4wLk5UY3hPRFE1T0RSak1EZzJZbUUxTXk1bVpUazNZMlF4TnpNeE9EZzJOakEwT1RRMk9ETTROekV6T1dObVlUVXlZV000TWpCa01qbGlZekJtWVRsbU1EazNOR05sWVRSbU9UUm1OMll6WkRFNE5qSTJObU13WmpnMFlqRTROR1poTnpZMk9EaGlaVEV3TURjNE5USmxZV1poWldNek5qQTRNek5pWVRCaU9UYzNZekl6T1dabU56YzBNV0pqWlRrd05R.OTk1NzQ5NzUxNGI2NGI0Ny41ZmI3ZjNiOWQyYTMxMmJkNjE1MTVlZWVlNDJhYWE1Y2Y4MzI2OGM3MDAzYjVlMzBkMmZhMWRjNmVhYTRhZWQ5NzBjMmJhNDJmYzA0ZGY5MWZjNDQ4NzgzNWRhNzg5NDQ2NDQxZDQ2NDQ4ZjMyOTQxNmFkMmFjNjliYmEwMzMwNg";
            var identity = Item.Import<Identity>(exported);
            Assert.IsNotNull(identity);
            Assert.AreEqual("io.dimeformat.ref", identity.SystemName);
            Assert.AreEqual(new Guid("08406d0e-7afa-44ed-be59-8a4b0d0d3476"), identity.UniqueId);
            Assert.AreEqual(new Guid("d01096b1-9c0b-49ce-bf98-f420f5a0ed62"), identity.SubjectId);
            Assert.AreEqual(DateTime.Parse("2022-07-01T10:00:13.636976Z").ToUniversalTime(), identity.IssuedAt);
            Assert.AreEqual(DateTime.Parse("2023-07-01T10:00:13.636976Z").ToUniversalTime(), identity.ExpiresAt);
            Assert.AreEqual(new Guid("2cbffde1-9f3d-4f38-939b-2e1fe748d8dc"), identity.IssuerId);
            Assert.AreEqual("2TDXdoNuQiCJ8agKrBmFqMXAveLAYcKQSkcFURJVHhoVPvRDy3gMKLKvt", identity.PublicKey.Public);
            Assert.IsTrue(identity.HasCapability(IdentityCapability.Generic));
            Assert.IsNotNull(identity.TrustChain);
            var key = Item.Import<Key>(
                "Di:KEY.eyJ1aWQiOiJjZTE3YzNhNC0xNjk2LTRjYjktOTNjNy1iZjYwY2NjYjE4Y2QiLCJpYXQiOiIyMDIyLTA3LTAxVDA5OjU4OjU5LjAwNDY2WiIsImtleSI6IlMyMVRaU0xOeEU1elFERWpidkR5QmpLUjZEV3BIQnhnTTdKMmJrS0o5OHEyQ3V3VG00ZzgxQzg5VmphQURNWUI1M0tGYkRLZ0hKdWF5M2VDa0JUZWc2ZEtoS0dodGRCTFduQTMiLCJwdWIiOiIyVERYZG9OdVFpQ0o4YWdLckJtRnFNWEF2ZUxBWWNLUVNrY0ZVUkpWSGhvVlB2UkR5M2dNS0xLdnQifQ");
            var message = new Message(Guid.NewGuid());
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(key);
            message.Verify(identity.PublicKey);
        }

    }

}
