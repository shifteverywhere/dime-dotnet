//
//  IdentityTests.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Threading;
using DiME;
using DiME.Capability;
using DiME.Exceptions;

namespace DiME_test;

[TestClass]
public class IdentityTests
{

    [TestMethod]
    public void GetHeaderTest1()
    {
        var identity = new Identity();
        Assert.AreEqual("ID", identity.Header);
        Assert.AreEqual("ID", Identity.ItemHeader);
    }
    
    [TestMethod]
    public void ClaimTest1() 
    {
        var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
        var identity = IdentityIssuingRequest.Generate(Commons.AudienceKey, caps).SelfIssue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.AudienceKey, Commons.SystemName);
        Assert.IsNotNull(identity.GetClaim<string>(Claim.Pub));
        Assert.AreEqual(Commons.AudienceKey.GetClaim<string>(Claim.Pub), identity.GetClaim<string>(Claim.Pub));
    }

    [TestMethod]
    public void ClaimTest2() 
    {
        var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
        var identity = IdentityIssuingRequest.Generate(Commons.AudienceKey, caps).SelfIssue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.AudienceKey, Commons.SystemName);
        identity.Strip();
        identity.PutClaim(Claim.Amb, new List<string>() { "one", "two" });
        Assert.IsNotNull(identity.GetClaim<List<string>>(Claim.Amb));
        identity.PutClaim(Claim.Aud, Guid.NewGuid());
        Assert.IsNotNull(identity.GetClaim<Guid>(Claim.Aud));
        Assert.AreNotEqual(default, identity.GetClaim<Guid>(Claim.Aud));
        identity.PutClaim(Claim.Ctx, Commons.Context);
        Assert.IsNotNull(identity.GetClaim<string>(Claim.Ctx));
        identity.PutClaim(Claim.Exp, DateTime.UtcNow);
        Assert.IsNotNull(identity.GetClaim<DateTime>(Claim.Exp));
        Assert.AreNotEqual(default, identity.GetClaim<DateTime>(Claim.Exp));
        identity.PutClaim(Claim.Iat, DateTime.UtcNow);
        Assert.IsNotNull(identity.GetClaim<DateTime>(Claim.Iat));
        Assert.AreNotEqual(default, identity.GetClaim<DateTime>(Claim.Iat));
        identity.PutClaim(Claim.Iss, Guid.NewGuid());
        Assert.IsNotNull(identity.GetClaim<Guid>(Claim.Iss));
        Assert.AreNotEqual(default, identity.GetClaim<Guid>(Claim.Iss));
        identity.PutClaim(Claim.Isu, Commons.IssuerUrl);
        Assert.IsNotNull(identity.GetClaim<string>(Claim.Isu));
        identity.PutClaim(Claim.Kid, Guid.NewGuid());
        Assert.IsNotNull(identity.GetClaim<Guid>(Claim.Kid));
        Assert.AreNotEqual(default, identity.GetClaim<Guid>(Claim.Kid));
        identity.PutClaim(Claim.Mtd, new List<string>() { "abc", "def" });
        Assert.IsNotNull(identity.GetClaim<List<string>>(Claim.Mtd));
        var pri = new Dictionary<string, object>
        {
            ["tag"] = Commons.Payload
        };
        identity.PutClaim(Claim.Pri, pri);
        Assert.IsNotNull(identity.GetClaim<Dictionary<string, object>>(Claim.Pri));
        Assert.AreNotEqual(default,identity.GetClaim<Dictionary<string, object>>(Claim.Pri));
        identity.PutClaim(Claim.Sub, Guid.NewGuid());
        Assert.IsNotNull(identity.GetClaim<Guid>(Claim.Sub));
        Assert.AreNotEqual(default, identity.GetClaim<Guid>(Claim.Sub));
        identity.PutClaim(Claim.Sys, Commons.SystemName);
        Assert.IsNotNull(identity.GetClaim<string>(Claim.Sys));
        identity.PutClaim(Claim.Uid, Guid.NewGuid());
        Assert.IsNotNull(identity.GetClaim<Guid>(Claim.Uid));
        Assert.AreNotEqual(default, identity.GetClaim<Guid>(Claim.Uid));
        try { identity.PutClaim(Claim.Cap, new List<KeyCapability>() { KeyCapability.Encrypt }); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { identity.PutClaim(Claim.Key,Commons.IssuerKey.Secret); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { identity.PutClaim(Claim.Lnk, new ItemLink(Commons.IssuerKey)); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { identity.PutClaim(Claim.Mim, Commons.Mimetype); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well*/ }
        try { identity.PutClaim(Claim.Pub, Commons.IssuerKey.Public); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest3() 
    {
        var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
        var identity = IdentityIssuingRequest.Generate(Commons.AudienceKey, caps).SelfIssue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.AudienceKey, Commons.SystemName);
        try { identity.RemoveClaim(Claim.Iss); Assert.IsTrue(false, "Exception not thrown."); } catch (InvalidOperationException) { /* all is well */ }
        try { identity.PutClaim(Claim.Exp, DateTime.UtcNow); } catch (InvalidOperationException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest4() 
    {
        var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
        var identity = IdentityIssuingRequest.Generate(Commons.AudienceKey, caps).SelfIssue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.AudienceKey, Commons.SystemName);
        identity.Strip();
        identity.RemoveClaim(Claim.Iss);
        identity.PutClaim(Claim.Iat, DateTime.UtcNow);
    }
    
    [TestMethod]
    public void IssueTest1()
    {
        Commons.ClearKeyRing();
        var subjectId = Guid.NewGuid();
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);            
        var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
        var identity = IdentityIssuingRequest.Generate(key, caps).SelfIssue(subjectId, Dime.ValidFor1Year * 10, key, Commons.SystemName);
        Assert.AreEqual(Commons.SystemName, identity.GetClaim<string>(Claim.Sys));
        Assert.AreEqual(subjectId, identity.GetClaim<Guid>(Claim.Sub));
        Assert.AreEqual(subjectId, identity.GetClaim<Guid>(Claim.Iss));
        Assert.IsTrue(identity.HasCapability(caps[0]));
        Assert.IsTrue(identity.HasCapability(caps[1]));
        Assert.IsTrue(identity.HasCapability(IdentityCapability.Self));
        Assert.IsNotNull(identity.PublicKey);
        Assert.AreEqual(key.Public, identity.PublicKey.Public);
        Assert.IsNotNull(identity.GetClaim<DateTime>(Claim.Iat));
        Assert.IsNotNull(identity.GetClaim<DateTime>(Claim.Exp));
        Assert.IsTrue(identity.GetClaim<DateTime>(Claim.Iat) < identity.GetClaim<DateTime>(Claim.Exp));
        Assert.AreEqual(subjectId, identity.GetClaim<Guid>(Claim.Iss));
    }

    [TestMethod]
    public void IssueTest2()
    {
        Commons.InitializeKeyRing();
        var subjectId = Guid.NewGuid();
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Identify };
        var iir = IdentityIssuingRequest.Generate(key, caps);
        var identity = iir.Issue(subjectId, Dime.ValidFor1Year, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
        Assert.AreEqual(Commons.TrustedIdentity.GetClaim<string>(Claim.Sys), identity.GetClaim<string>(Claim.Sys));
        Assert.AreEqual(subjectId, identity.GetClaim<Guid>(Claim.Sub));
        Assert.IsTrue(identity.HasCapability(caps[0]));
        Assert.IsTrue(identity.HasCapability(caps[1]));
        Assert.IsNotNull(identity.PublicKey);
        Assert.AreEqual(key.Public, identity.PublicKey.Public);
        Assert.IsNotNull(identity.GetClaim<DateTime>(Claim.Iat));
        Assert.IsNotNull(identity.GetClaim<DateTime>(Claim.Exp));
        Assert.IsTrue(identity.GetClaim<DateTime>(Claim.Iat) < identity.GetClaim<DateTime>(Claim.Exp));
        Assert.IsTrue(Commons.IntermediateIdentity.GetClaim<Guid>(Claim.Sub) == identity.GetClaim<Guid>(Claim.Iss));
    }

    [TestMethod]
    public void IssueTest3()
    {
        Commons.InitializeKeyRing();
        var reqCaps = new List<IdentityCapability> { IdentityCapability.Issue };
        var allowCaps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Identify };
        try {
            _ = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), reqCaps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, true, allowCaps);
        } catch (CapabilityException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void IssueTest4()
    {
        Commons.InitializeKeyRing();
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var caps = new List<IdentityCapability> { IdentityCapability.Issue, IdentityCapability.Generic };
        var identity = IdentityIssuingRequest.Generate(key, caps).Issue(Guid.NewGuid(), Dime.ValidFor1Minute, Commons.TrustedKey, Commons.TrustedIdentity, true, caps);
        Assert.IsTrue(identity.HasCapability(IdentityCapability.Issue));
        Assert.IsTrue(identity.HasCapability(IdentityCapability.Generic));
    }

    [TestMethod]
    public void IssueTest5()
    {
        Commons.ClearKeyRing();
        var caps = new List<IdentityCapability> { IdentityCapability.Issue };
        try { _ = IdentityIssuingRequest.Generate(Key.Generate(KeyCapability.Sign), caps).Issue(Guid.NewGuid(), Dime.ValidFor1Minute, Commons.TrustedKey, null, true, caps);  Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentNullException) { /* all is well */ }
    }

    [TestMethod]
    public void IsSelfSignedTest1()
    {
        Commons.ClearKeyRing();
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons.SystemName);
        Assert.IsTrue(identity.IsSelfSigned);
    }

    [TestMethod]
    public void IsSelfSignedTest2()
    {
        Commons.InitializeKeyRing();
        var caps = new List<IdentityCapability> { IdentityCapability.Generic };
        var identity = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null)).Issue(Guid.NewGuid(), 100L, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
        Assert.IsFalse(identity.IsSelfSigned);
    }

    [TestMethod]
    public void VerifyTest1()
    {
        Commons.ClearKeyRing();
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var identity = IdentityIssuingRequest.Generate(key)
            .SelfIssue(Guid.NewGuid(), 100L, key, Commons.SystemName);
        Assert.IsTrue(identity.IsSelfSigned);
        Assert.IsFalse(Dime.IsIntegrityStateValid(identity.Verify()));
    }

    [TestMethod]
    public void VerifyTest2()
    {
        Commons.InitializeKeyRing();
        var caps = new List<IdentityCapability> { IdentityCapability.Generic };
        var identity = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null)).Issue(Guid.NewGuid(), 100L, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
        Assert.IsTrue(Dime.IsIntegrityStateValid(identity.Verify()));
    }

    [TestMethod]
    public void VerifyTest3()
    {
        Commons.ClearKeyRing();
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var identity = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons.SystemName);
        Commons.InitializeKeyRing();
        Assert.IsFalse(Dime.IsIntegrityStateValid(identity.Verify()));
    }

    [TestMethod]
    public void VerifyTest4()
    {
        Commons.InitializeKeyRing();
        Assert.IsTrue(Dime.IsIntegrityStateValid(Commons.IntermediateIdentity.Verify()));
    }
        
    [TestMethod]
    public void VerifyTest5()
    {
        Commons.InitializeKeyRing();
        Assert.IsTrue(Dime.IsIntegrityStateValid(Commons.AudienceIdentity.Verify()));
    }
        
    [TestMethod]
    public void VerifyTest6()
    {
        Commons.ClearKeyRing();
        Assert.IsTrue(Dime.IsIntegrityStateValid(Commons.AudienceIdentity.Verify(Commons.IntermediateIdentity)));
    }
        
    [TestMethod]
    public void VerifyTest7()
    {
        Commons.ClearKeyRing();
        Assert.IsFalse(Dime.IsIntegrityStateValid(Commons.AudienceIdentity.Verify(Commons.IssuerIdentity)));
    }
        
    [TestMethod]
    public void VerifyTest8() 
    {
        Commons.InitializeKeyRing();
        var nodeCaps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
        var key1 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var node1 = IdentityIssuingRequest.Generate(key1, nodeCaps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, true, nodeCaps, nodeCaps);
        var key2 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var node2 = IdentityIssuingRequest.Generate(key2, nodeCaps).Issue(Guid.NewGuid(), 100L, key1, node1, true, nodeCaps, nodeCaps);
        var key3 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var node3 = IdentityIssuingRequest.Generate(key3, nodeCaps).Issue(Guid.NewGuid(), 100L, key2, node2, true, nodeCaps, nodeCaps);
        var leafCaps = new List<IdentityCapability> { IdentityCapability.Generic };
        var leaf = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), leafCaps).Issue(Guid.NewGuid(), 100L, key3, node3, true, leafCaps, leafCaps);
        Assert.IsTrue(Dime.IsIntegrityStateValid(leaf.Verify()));
        Assert.IsFalse(Dime.IsIntegrityStateValid(leaf.Verify(node1)));
        Assert.IsFalse(Dime.IsIntegrityStateValid(leaf.Verify(node2)));
        Assert.IsTrue(Dime.IsIntegrityStateValid(leaf.Verify(node3)));
        Assert.IsFalse(Dime.IsIntegrityStateValid(leaf.Verify(Commons.IntermediateIdentity)));
    }
        
    [TestMethod]
    public void VerifyTest9() 
    {
        Commons.InitializeKeyRing();
        var nodeCaps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Issue };
        var key1 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var node1 = IdentityIssuingRequest.Generate(key1, nodeCaps).Issue(Guid.NewGuid(), 100L, Commons.TrustedKey, Commons.TrustedIdentity, false, nodeCaps, nodeCaps);
        var key2 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var node2 = IdentityIssuingRequest.Generate(key2, nodeCaps).Issue(Guid.NewGuid(), 100L, key1, node1, false, nodeCaps, nodeCaps);
        var leafCaps = new List<IdentityCapability> { IdentityCapability.Generic };
        var leaf = IdentityIssuingRequest.Generate(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null), leafCaps).Issue(Guid.NewGuid(), 100L, key2, node2, false, leafCaps, leafCaps);
        Assert.IsFalse(Dime.IsIntegrityStateValid(leaf.Verify()));
        Assert.IsFalse(Dime.IsIntegrityStateValid(leaf.Verify(node1)));
        Assert.IsTrue(Dime.IsIntegrityStateValid(leaf.Verify(node2)));
        Assert.IsFalse(Dime.IsIntegrityStateValid(leaf.Verify(Commons.IntermediateIdentity)));
    }
        
    [TestMethod] 
    public void VerifyTest10()
    {
        Commons.InitializeKeyRing();
        var caps = new List<IdentityCapability> { IdentityCapability.Generic };
        var identity = IdentityIssuingRequest.Generate(Key.Generate(KeyCapability.Sign)).Issue(Guid.NewGuid(), 1L, Commons.TrustedKey, Commons.TrustedIdentity, false, caps, caps);
        Thread.Sleep(1001);
        Assert.IsFalse(Dime.IsIntegrityStateValid(identity.Verify()));
        Dime.GracePeriod = 1L;
        Assert.IsTrue(Dime.IsIntegrityStateValid(identity.Verify()));
        Dime.GracePeriod = 0L;
    }

    [TestMethod]
    public void VerifyTest11() 
    {
        Commons.InitializeKeyRing();
        var caps = new List<IdentityCapability> { IdentityCapability.Generic };
        var identity = IdentityIssuingRequest.Generate(Key.Generate(KeyCapability.Sign)).Issue(Guid.NewGuid(), 1L, Commons.TrustedKey, Commons.TrustedIdentity, false, caps, caps);
        Thread.Sleep(2000);
        Dime.TimeModifier = -2L;
        Assert.IsTrue(Dime.IsIntegrityStateValid(identity.Verify()));
    }

    [TestMethod]
    public void VerifyTest12() 
    {
        Dime.TimeModifier = -2L;
        Commons.InitializeKeyRing();
        var caps = new List<IdentityCapability> { IdentityCapability.Generic };
        var identity = IdentityIssuingRequest.Generate(Key.Generate(KeyCapability.Sign)).Issue(Guid.NewGuid(), 1L, Commons.TrustedKey, Commons.TrustedIdentity, false, caps, caps);
        Thread.Sleep(2000);
        Assert.IsFalse(Dime.IsIntegrityStateValid(identity.Verify()));
    }

    [TestMethod]
    public void ExportTest1()
    {
        Commons.InitializeKeyRing();
        var caps = new List<IdentityCapability> { IdentityCapability.Generic, IdentityCapability.Identify };
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var identity = IdentityIssuingRequest.Generate(key, caps).Issue(Guid.NewGuid(), Dime.ValidFor1Year, Commons.IntermediateKey, Commons.IntermediateIdentity, true, caps);
        var exported = identity.Export();
        Assert.IsNotNull(exported);
        Assert.IsTrue(exported.Length > 0);
        Assert.IsTrue(exported.StartsWith($"{Envelope.ItemHeader}:{Identity.ItemHeader}"));
        Assert.AreEqual(4, exported.Split(new[] { '.' }).Length);
    }

    [TestMethod]
    public void ImportTest1()
    {
        Commons.InitializeKeyRing();
        const string exported = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il0sImV4cCI6IjIwMjMtMTAtMjRUMjI6NDQ6NTUuNDk2NDYzWiIsImlhdCI6IjIwMjItMTAtMjRUMjI6NDQ6NTUuNDk2NDYzWiIsImlzcyI6IjE3NWM2YTI4LTQ2OTktNGNhMy05MWMwLTk1NTU2OWFjOTE2OSIsInB1YiI6IkRTQy4vdEtFSzFFdnZMc3AzbzlPMHhhd2VDLzU3RVJ0blNGY2I0ZnJUZFBFM2tJIiwic3ViIjoiY2UyNjY5YzgtMDVlYS00M2U5LThiNGUtYjM0Y2Y4Y2Q1ZDkxIiwic3lzIjoiaW8uZGltZWZvcm1hdC5yZWYiLCJ1aWQiOiIxNjg1MTdkYS00MmRkLTQ4YmItYTgwMy0zNWUzNzlhZGNmZmIifQ.SUQuZXlKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFN3aVpYaHdJam9pTWpBeU55MHhNQzB5TTFReU1qb3pOVG8wTkM0d09EVTBNVGhhSWl3aWFXRjBJam9pTWpBeU1pMHhNQzB5TkZReU1qb3pOVG8wTkM0d09EVTBNVGhhSWl3aWFYTnpJam9pWlRCbE5tTmlZVFl0WW1RMFpDMDBOV1JrTFRneU16UXRNRE5oWm1SbFlXVTVNRFJoSWl3aWNIVmlJam9pUkZORExrZFNhVXhEUW5aVVVHcG1NemRYY21ScFdEWXlRbVJZSzNkWVdGUTFRMWQ1U0d0a1kyOTJPR1JNZGtVaUxDSnpkV0lpT2lJeE56VmpObUV5T0MwME5qazVMVFJqWVRNdE9URmpNQzA1TlRVMU5qbGhZemt4TmpraUxDSnplWE1pT2lKcGJ5NWthVzFsWm05eWJXRjBMbkpsWmlJc0luVnBaQ0k2SWpaall6SXlNbU16TFdVMVpHTXROREl5WVMxaU9XWmpMVE13T0dVNFpEYzJaVGM1WWlKOS5aV1ZqT0RnelltWmlOR05oT0RWa01DNHhZVFJpWkRNMU5UZzFOVEZrTUdVeU1ETmxaamRpWW1aall6RmhabU0wTURJek1tWmpOV0V3Tm1JMlpEWmtPRFF4WVdKaU1HTTJNek5qTXpjM05tSmlNemM0TWpSbE1HRTJNbVV6T1dNellqWTFOVE5qT0RNMk1EZ3daVGcxTXpVNE1EZGpNVEppT0RWaU5UWXhZbVkwTjJJeE9XTXlPVEl3TkdNME1UVXdNdw.NDFlNmM2ODI5Y2VmNjdmZS43YzY2YjZlOTEyMTQ4ZTZiNjY3NDgwZGFjMDU1NDI4MzRlYjg4NTQwOWY4ZTM2OTI4YjhhZjBiMzdkYzVlMjE0MTJkZjg4ODljOTA2ODUyOGIxNTdhYzBkNzczY2UyODZlN2M1Yjg4OGEzNWUyYzIyYWFmOTNiNzIwMmQ0N2MwNg";
        var identity = Item.Import<Identity>(exported);
        Assert.IsNotNull(identity);
        Assert.AreEqual(Commons.SystemName, identity.GetClaim<string>(Claim.Sys));
        Assert.AreEqual(new Guid("168517da-42dd-48bb-a803-35e379adcffb"), identity.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(new Guid("ce2669c8-05ea-43e9-8b4e-b34cf8cd5d91"), identity.GetClaim<Guid>(Claim.Sub));
        Assert.AreEqual(DateTime.Parse("2022-10-24T22:44:55.496463Z").ToUniversalTime(), identity.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(DateTime.Parse("2023-10-24T22:44:55.496463Z").ToUniversalTime(), identity.GetClaim<DateTime>(Claim.Exp));
        Assert.AreEqual(Commons.IntermediateIdentity.GetClaim<Guid>(Claim.Sub), identity.GetClaim<Guid>(Claim.Iss));
        Assert.IsNotNull(identity.PublicKey);
        Assert.AreEqual("DSC./tKEK1EvvLsp3o9O0xaweC/57ERtnSFcb4frTdPE3kI", identity.PublicKey.Public);
        Assert.IsTrue(identity.HasCapability(IdentityCapability.Generic));
        Assert.IsTrue(identity.HasCapability(IdentityCapability.Identify));
        Assert.IsNotNull(identity.TrustChain);
        Assert.IsTrue(Dime.IsIntegrityStateValid(identity.Verify()));
    }

    [TestMethod]
    public void AmbitTest1() {
        var ambitList = new List<string>() { "global", "administrator" };
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
            
        var identity1 = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100, key, Commons.SystemName, ambitList);
        Assert.IsNotNull(identity1);
        var ambit1 = identity1.GetClaim<List<string>>(Claim.Amb);
        Assert.IsNotNull(ambit1);
        Assert.AreEqual(2, ambit1.Count);
        Assert.IsTrue(identity1.HasAmbit(ambitList[0]));
        Assert.IsTrue(identity1.HasAmbit(ambitList[1]));

        var identity2 = Item.Import<Identity>(identity1.Export());
        Assert.IsNotNull(identity2);
        var ambit2 = identity2.GetClaim<List<string>>(Claim.Amb);
        Assert.IsNotNull(ambit2);
        Assert.AreEqual(2, ambit2.Count);
        Assert.IsTrue(identity2.HasAmbit(ambitList[0]));
        Assert.IsTrue(identity2.HasAmbit(ambitList[1]));
    }

    [TestMethod]
    public void MethodsTest1() {
        var methods = new List<string> { "dime", "sov" };
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);

        var identity1 = IdentityIssuingRequest.Generate(key).SelfIssue(Guid.NewGuid(), 100L, key, Commons.SystemName, null, methods);
        Assert.IsNotNull(identity1);
        var methods1 = identity1.GetClaim<List<string>>(Claim.Mtd);
        Assert.IsNotNull(methods1);
        Assert.AreEqual(2, methods1.Count);
        Assert.IsTrue(methods1.Contains(methods[0]));
        Assert.IsTrue(methods1.Contains(methods[1]));

        var identity2 = Item.Import<Identity>(identity1.Export());
        Assert.IsNotNull(identity2);
        var methods2 = identity2.GetClaim<List<string>>(Claim.Mtd);
        Assert.IsNotNull(methods2);
        Assert.AreEqual(2, methods2.Count);
        Assert.IsTrue(methods2.Contains(methods[0]));
        Assert.IsTrue(methods2.Contains(methods[1]));
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
        Assert.IsNotNull(identity.Principles);
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
        Assert.IsNotNull(identity2.Principles);
        Assert.AreEqual( Commons.Payload, identity2.Principles["tag"]);
        var nbr = (List<string>) identity2.Principles["nbr"]; 
        Assert.AreEqual(3, nbr.Count);
        Assert.AreEqual("three", nbr[2]);
    }
    
}