//
//  KeyRingTests.cs
//  DiME - Data Identity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2022 Shift Everywhere AB. All rights reserved.
//
using System;
using System.Collections.Generic;
using System.Text;
using DiME;
using DiME.Capability;
using DiME.Exceptions;
using DiME.KeyRing;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace DiME_test;

[TestClass]
public class KeyRingTests
{
    
    [TestInitialize]
    public void BeforeAll()
    {
       Commons.ClearKeyRing();
    }

    [TestMethod]
    public void NoKeyRingTest1() {
        Commons.ClearKeyRing();
        Assert.IsTrue(Dime.KeyRing.IsEmpty);
        Commons.InitializeKeyRing();
        Assert.IsFalse(Dime.KeyRing.IsEmpty);
    }
    
    [TestMethod]
    public void NoKeyRingTest2()
    {
        Assert.AreEqual(IntegrityState.FailedNoKeyRing, Commons.AudienceIdentity.Verify());
        Assert.IsTrue(Dime.KeyRing.IsEmpty);
    }
    
    [TestMethod]
    public void VerifyTest1() 
    {
        Commons.InitializeKeyRing();
        Assert.AreEqual(IntegrityState.Complete, Commons.AudienceIdentity.Verify());
    }

    [TestMethod]
    public void VerifyTest2() 
    {
        Commons.InitializeKeyRing();
        var subjectId = Guid.NewGuid();
        var key = Key.Generate(KeyCapability.Sign);
        var caps = new List<IdentityCapability>() { IdentityCapability.Generic, IdentityCapability.Issue };
        var identity = IdentityIssuingRequest.Generate(key, caps).SelfIssue(subjectId, Dime.ValidFor1Year, key, Commons.SystemName);
        Assert.AreEqual(IntegrityState.FailedKeyMismatch, identity.Verify());
    }

    [TestMethod]
    public void VerifyTest3() 
    {
        Commons.InitializeKeyRing();
        var trustedKey = Key.Generate(KeyCapability.Sign);
        Dime.KeyRing.Put(trustedKey);
        var issuerKey = Key.Generate(KeyCapability.Sign);
        var issuerCaps = new List<IdentityCapability>() { IdentityCapability.Generic, IdentityCapability.Issue };
        var issuerIdentity = IdentityIssuingRequest.Generate(issuerKey, issuerCaps).SelfIssue(Guid.NewGuid(), Dime.ValidFor1Minute, issuerKey, Commons.SystemName);
        var caps = new List<IdentityCapability>() { IdentityCapability.Generic, IdentityCapability.Identify };
        var iir = IdentityIssuingRequest.Generate(Key.Generate(KeyCapability.Sign), caps);
        var identity = iir.Issue(Guid.NewGuid(), Dime.ValidFor1Minute, issuerKey, issuerIdentity, false, caps);
        Assert.IsFalse(Dime.IsIntegrityStateValid(identity.Verify()));
        identity.Sign(trustedKey); // signs the identity with another trusted key
        Assert.IsTrue(Dime.IsIntegrityStateValid(identity.Verify()));
    }

    [TestMethod]
    public void VerifyTest4() 
    {
            var trustedKey = Key.Generate(KeyCapability.Sign);
            Dime.KeyRing.Put(trustedKey);
            var data = new Data(Guid.NewGuid());
            data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
            data.Sign(trustedKey);
            Assert.IsTrue(Dime.IsIntegrityStateValid(data.Verify()));
            Dime.KeyRing.Remove(trustedKey);
            Assert.AreEqual(IntegrityState.Complete, data.Verify(trustedKey));
    }

    [TestMethod]
    public void VerifyTest5() 
    {
        var trustedKey = Key.Generate(KeyCapability.Sign);
        Dime.KeyRing.Put(trustedKey);
        Dime.KeyRing.Put(Key.Generate(KeyCapability.Sign));
        var data = new Data(Guid.NewGuid());
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        data.Sign(trustedKey);
        Assert.IsTrue(Dime.IsIntegrityStateValid(data.Verify()));
        Dime.KeyRing.Remove(trustedKey);
        Assert.AreEqual(IntegrityState.FailedKeyMismatch , data.Verify());
    }

    [TestMethod]
    public void VerifyTest6() 
    {
        var trustedKey = Key.Generate(KeyCapability.Sign);
        var data = new Data(Guid.NewGuid());
        data.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        data.Sign(trustedKey);
        var importedKey = Item.Import<Key>(trustedKey.PublicCopy().Export());
        Dime.KeyRing.Put(importedKey);
        Assert.IsTrue(Dime.IsIntegrityStateValid(data.Verify()));
    }

    [TestMethod]
    public void KeyRingTest1() 
    {
        Commons.InitializeKeyRing();
        Assert.AreEqual(1, Dime.KeyRing.Size);
        var key = Key.Generate(KeyCapability.Sign);
        Dime.KeyRing.Put(key);
        Assert.AreEqual(2, Dime.KeyRing.Size);
        Dime.KeyRing.Remove(key);
        Assert.AreEqual(1, Dime.KeyRing.Size);
        Dime.KeyRing.Clear();
        Assert.AreEqual(0, Dime.KeyRing.Size);
        Assert.IsTrue(Dime.KeyRing.IsEmpty);
    }

    [TestMethod]
    public void KeyRingTest2() 
    {
        Commons.InitializeKeyRing();
        Assert.IsTrue(Dime.KeyRing.Contains(Commons.TrustedIdentity));
        Dime.KeyRing.Remove(Commons.TrustedIdentity);
        Assert.IsFalse(Dime.KeyRing.Contains(Commons.TrustedIdentity));
    }

    [TestMethod]
    public void KeyRingTest3() 
    {
        var trustedKey = Key.Generate(KeyCapability.Sign);
        Dime.KeyRing.Put(trustedKey);
        var publicKey = trustedKey.PublicCopy();
        Dime.KeyRing.Contains(publicKey);
        var encoded = publicKey.Export();
        var importedKey = Item.Import<Key>(encoded);
        Assert.IsTrue(Dime.KeyRing.Contains(importedKey));
        Dime.KeyRing.Remove(importedKey);
        Assert.IsFalse(Dime.KeyRing.Contains(trustedKey));
    }

    [TestMethod]
    public void ExportTest1() 
    {
        Commons.InitializeKeyRing();
        Dime.KeyRing.Put(Key.Generate(KeyCapability.Sign));
        var encoded = Dime.KeyRing.Export(Commons.TrustedKey);
        Assert.IsNotNull(encoded);
        Assert.IsTrue(encoded.StartsWith(Envelope.ItemHeader));
        var components = encoded.Split(':');
        Assert.AreEqual(4, components.Length);
    }

    [TestMethod]
    public void ImportTest1() 
    {
        Assert.AreEqual(0, Dime.KeyRing.Size);
        const string encoded = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDM0LTAxLTIzVDE0OjQ2OjE1Ljc5MTc4NFoiLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5MTc4NFoiLCJpc3MiOiI2NTQ5OGYxNy1jMzI1LTQ3OWMtYmY5Yy04NWE0ZmJlOGEwYjAiLCJwdWIiOiJOYUNsLlFzQXpRclpJUGpPK05kaS9zQzlIRmE2REZCMEZmTUhva09xMU5ab3ovdlEiLCJzdWIiOiI2NTQ5OGYxNy1jMzI1LTQ3OWMtYmY5Yy04NWE0ZmJlOGEwYjAiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6ImMyNGFjM2U2LTZlN2MtNDNiOS1iNjUzLTAxY2E3MmM0N2Y2MCJ9.MWZhODZlZWQzYmEzNTczOC41NTkyYzM3Mjc0MGY4MjQxZWMzZTg0ZmMyY2U5YzU5MGY1MjdmNmZlMjhhMjY4YWEzNzM4NWI5MTljMzEzM2ZlMjc5MmYwNjNhOWE5NWYzMmEwODBkOWYyYzk1NjQ0MGQ1NzIxODRhOGEzYzViNDIyYjE1ZjgyNjkwMzNiNmUwNA:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE1OjAxOjM2LjE3OTg1NzNaIiwia2V5IjoiTmFDbC5JMVlyN1l3S3p1T01MQ3g2ZXZrOW1aTEFPMU9EcEdqdFBtc0hJZ04zc1YySFd1Q3AyZys5RzQvRnl1Ym43K291bE52Q2pYUG5LQTdSQkFaSzdHbWxCdyIsInB1YiI6Ik5hQ2wuaDFyZ3Fkb1B2UnVQeGNybTUrL3FMcFRid28xejV5Z08wUVFHU3V4cHBRYyIsInVpZCI6ImNiNWIzYjU4LTI3NGEtNDhkZS1iMmY5LWFjMDVlNzNkZjQwZCJ9:MWZhODZlZWQzYmEzNTczOC40ZGQ5ZTYyMWI4M2ZjZTczODdmOTEyMjgzNDcyOWMyYzE4YmRjZGFjZWNhM2E3Y2JhZmIzMTI5NDQyN2U3OWM4Y2I3NjQ4NDU0N2Y5NDY0Yzk5ZmRkMGE3NmMzOTg3NTQ5YjI2YWZjYzVhZmM5YmM1YmYzNWU1YzI3N2M4NTUwNw";
        Dime.KeyRing.Import(encoded, Commons.TrustedKey);
        Assert.AreEqual(2, Dime.KeyRing.Size);
        Assert.IsTrue(Dime.IsIntegrityStateValid(Commons.AudienceIdentity.Verify()));
    }

    [TestMethod]
    public void ImportTest2() {
        Assert.AreEqual(0, Dime.KeyRing.Size);
        const string encoded = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDM0LTAxLTIzVDE0OjQ2OjE1Ljc5MTc4NFoiLCJpYXQiOiIyMDI0LTAxLTI2VDE0OjQ2OjE1Ljc5MTc4NFoiLCJpc3MiOiI2NTQ5OGYxNy1jMzI1LTQ3OWMtYmY5Yy04NWE0ZmJlOGEwYjAiLCJwdWIiOiJOYUNsLlFzQXpRclpJUGpPK05kaS9zQzlIRmE2REZCMEZmTUhva09xMU5ab3ovdlEiLCJzdWIiOiI2NTQ5OGYxNy1jMzI1LTQ3OWMtYmY5Yy04NWE0ZmJlOGEwYjAiLCJzeXMiOiJpby5kaW1lZm9ybWF0LnJlZiIsInVpZCI6ImMyNGFjM2U2LTZlN2MtNDNiOS1iNjUzLTAxY2E3MmM0N2Y2MCJ9.MWZhODZlZWQzYmEzNTczOC41NTkyYzM3Mjc0MGY4MjQxZWMzZTg0ZmMyY2U5YzU5MGY1MjdmNmZlMjhhMjY4YWEzNzM4NWI5MTljMzEzM2ZlMjc5MmYwNjNhOWE5NWYzMmEwODBkOWYyYzk1NjQ0MGQ1NzIxODRhOGEzYzViNDIyYjE1ZjgyNjkwMzNiNmUwNA:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE1OjAxOjM2LjE3OTg1NzNaIiwia2V5IjoiTmFDbC5JMVlyN1l3S3p1T01MQ3g2ZXZrOW1aTEFPMU9EcEdqdFBtc0hJZ04zc1YySFd1Q3AyZys5RzQvRnl1Ym43K291bE52Q2pYUG5LQTdSQkFaSzdHbWxCdyIsInB1YiI6Ik5hQ2wuaDFyZ3Fkb1B2UnVQeGNybTUrL3FMcFRid28xejV5Z08wUVFHU3V4cHBRYyIsInVpZCI6ImNiNWIzYjU4LTI3NGEtNDhkZS1iMmY5LWFjMDVlNzNkZjQwZCJ9";
        try {
            Dime.KeyRing.Import(encoded, Commons.TrustedKey);
        } catch (IntegrityStateException e) {
            Assert.AreEqual(IntegrityState.FailedNoSignature, e.State);
        }
    }
    
}