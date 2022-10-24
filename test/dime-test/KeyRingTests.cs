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
        const string encoded = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDMyLTEwLTIxVDIyOjM1OjQ0LjA4MTc4NFoiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjM1OjQ0LjA4MTc4NFoiLCJpc3MiOiJlMGU2Y2JhNi1iZDRkLTQ1ZGQtODIzNC0wM2FmZGVhZTkwNGEiLCJwdWIiOiJEU0MuUmovRzkyd3ZyQ000SmkvVjZZVVdWNlRBMzRnR3V2cXI4UGNCRGRLeEZXTSIsInN1YiI6ImUwZTZjYmE2LWJkNGQtNDVkZC04MjM0LTAzYWZkZWFlOTA0YSIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiYjlkOTM2ZGYtMjU4ZS00ZjJmLTkyZDUtN2JmYTE0YmFjMzhkIn0.ZWVjODgzYmZiNGNhODVkMC5hNDhjYzM2ZjhkN2Y1MmIxYmIxNTczZjA1YTk1NTVlYzM0NjU2MDVlZDkxZjk3OWM2ZTA5MDlkN2E2OTRiNjk3YzY5NzY5ZjkxNGQ0NzgyZGJhY2Y0YTg1Mjg4ZjNlYWYzMzQwMmI3NmUyMTI0M2I2MjQzOWE1ZmY2YjlkYzQwYg:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjQ4OjA5LjA0NDgwNVoiLCJrZXkiOiJEU0MuaUZ4aTNvTnZXQXlyOG1Jb1hqcU95cERDZEZKZmF6WjZwSWdlNitMMGpZZzNzSUlrNnpXWGFwM20wMVpiTjlIRjNzb093aDQ2bXgwNW5iZVNlaU1STHciLCJwdWIiOiJEU0MuTjdDQ0pPczFsMnFkNXROV1d6ZlJ4ZDdLRHNJZU9wc2RPWjIza25vakVTOCIsInVpZCI6IjRiZWY3NzZjLTdiMDgtNDI4NC1hNTQxLTNmYTdkZDBhZTdjNiJ9:ZWVjODgzYmZiNGNhODVkMC5hM2JjNzc5MDRhMTgyNjgxZmJhYWFmZGExOWZjMGZhZTEzMGY1YWZkZDk5MGYyMjU3NWRmMzNiYjEyNDk3NzQxNjVkZGQ4MzQ3OGIwYTYzNmU5ODc0YWQ5YWU1NjUxNWYzYzE0YjQ1NTBkNWE5OTYyYzNhZGQ2Yjg0NGE0ZjQwMw";
        Dime.KeyRing.Import(encoded, Commons.TrustedKey);
        Assert.AreEqual(2, Dime.KeyRing.Size);
        Assert.IsTrue(Dime.IsIntegrityStateValid(Commons.AudienceIdentity.Verify()));
    }

    [TestMethod]
    public void ImportTest2() {
        Assert.AreEqual(0, Dime.KeyRing.Size);
        const string encoded = "Di:ID.eyJjYXAiOlsiZ2VuZXJpYyIsImlzc3VlIiwic2VsZiJdLCJleHAiOiIyMDMyLTA5LTMwVDE0OjQxOjUzLjEyMTUwMFoiLCJpYXQiOiIyMDIyLTEwLTAzVDE0OjQxOjUzLjEyMTUwMFoiLCJpc3MiOiJiNDNjNDgyOC0wOTYxLTRiZDYtYjdhYy1lNzZiOTg4YmFmZjAiLCJwdWIiOiJTVE4uZFgycVJtWWZ2eFRNdVZIeml2a1hjUU0zQWROMm44aEhoRkJ2ZnNENDhXVGVzcjRZVSIsInN1YiI6ImI0M2M0ODI4LTA5NjEtNGJkNi1iN2FjLWU3NmI5ODhiYWZmMCIsInN5cyI6ImlvLmRpbWVmb3JtYXQucmVmIiwidWlkIjoiMTU3NGZkZDEtMDRkOC00MjRjLTgyYjItZjkxMDFkNTliYjI3In0.MjY3MDU3ZmQ5N2UyMDNmNi41MjI1NDExMjhhOGNhZTViYWI5MTQ1ZDdjYTFlNWIxMzYyZTU3Mzg5ZjE5NjQyMjhiNjZmZWYwZDdjYmUwYzM0YTM1YzA3YWRmMzIwMWFmNDU1ZmMwNjBiM2E5NmY5MzlkNTQ3ZGIwZGFmZTMzNWJmN2MyZjc1YmFhNjVjNjAwYg:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDIyLTEwLTA2VDEzOjIxOjQ5LjU4OTQyMFoiLCJrZXkiOiJTVE4uRkhCb2tlRkVoSm1ndkVhcXBoV05UbWdjblQ4N3ZhU0RDRGY3aHRxdDlZR0hFYzRVNmRlWHFTdEZjUDczNnpRWktpZjZ0VFJWVVN0b0gxREFBWk4xdjF6REpIOTU0IiwicHViIjoiU1ROLlVWM3Z6b0JnUUdieXppS1YyZnVhSEtIczlkYnI5UVVqOGt2UDExeE5SRjRtRWRIVnIiLCJ1aWQiOiIzNTEyNjg4Yi0wYWQ2LTQ1MjItYjVkYi05Mzk4MTliODc2NDYifQ";
        try {
            Dime.KeyRing.Import(encoded, Commons.TrustedKey);
        } catch (IntegrityStateException e) {
            Assert.AreEqual(IntegrityState.FailedNoSignature, e.State);
        }
    }
    
}