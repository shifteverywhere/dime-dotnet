//
//  KeyTests.cs
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
using System.Text;
using DiME;
using DiME.Capability;

namespace DiME_test;

[TestClass]
public class KeyTests
{
        
    [TestMethod]
    public void GetHeaderTest1()
    {
        var key = new Key();
        Assert.AreEqual("KEY", key.Header);
        Assert.AreEqual("KEY", Key.ItemHeader);
    }
    
    [TestMethod]
    public void ClaimTest1()
    {
        var key = Key.Generate(KeyCapability.Sign);
        Assert.AreEqual(default, key.GetClaim<Guid>(Claim.Iss));
        key.PutClaim(Claim.Iss, Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub));
        Assert.AreEqual(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), key.GetClaim<Guid>(Claim.Iss));
    }

    [TestMethod]
    public void ClaimTest2() 
    {
        var key = Key.Generate(KeyCapability.Sign);
        Assert.AreNotEqual(default, key.GetClaim<DateTime>(Claim.Iat));
        key.RemoveClaim(Claim.Iat);
        Assert.AreEqual(default, key.GetClaim<DateTime>(Claim.Iat));
    }

    [TestMethod]
    public void ClaimTest3() 
    {
        var key = Key.Generate(KeyCapability.Sign);
        key.PutClaim(Claim.Amb, new List<string>() { "one", "two" });
        Assert.IsNotNull(key.GetClaim<List<string>>(Claim.Amb));
        key.PutClaim(Claim.Aud, Guid.NewGuid());
        Assert.IsNotNull(key.GetClaim<Guid>(Claim.Aud));
        Assert.AreNotEqual(default, key.GetClaim<Guid>(Claim.Aud));
        key.PutClaim(Claim.Ctx, Commons.Context);
        Assert.IsNotNull(key.GetClaim<string>(Claim.Ctx));
        key.PutClaim(Claim.Exp, DateTime.UtcNow);
        Assert.IsNotNull(key.GetClaim<DateTime>(Claim.Exp));
        Assert.AreNotEqual(default, key.GetClaim<DateTime>(Claim.Exp));
        key.PutClaim(Claim.Iat, DateTime.UtcNow);
        Assert.IsNotNull(key.GetClaim<DateTime>(Claim.Iat));
        Assert.AreNotEqual(default, key.GetClaim<DateTime>(Claim.Iat));
        key.PutClaim(Claim.Iss, Guid.NewGuid());
        Assert.IsNotNull(key.GetClaim<Guid>(Claim.Iss));
        Assert.AreNotEqual(default, key.GetClaim<Guid>(Claim.Iss));
        key.PutClaim(Claim.Kid, Guid.NewGuid());
        Assert.IsNotNull(key.GetClaim<Guid>(Claim.Kid));
        Assert.AreNotEqual(default, key.GetClaim<Guid>(Claim.Kid));
        key.PutClaim(Claim.Mtd, new List<string>() { "abc", "def" });
        Assert.IsNotNull(key.GetClaim<List<string>>(Claim.Mtd));
        key.PutClaim(Claim.Sub, Guid.NewGuid());
        Assert.IsNotNull(key.GetClaim<Guid>(Claim.Sub));
        Assert.AreNotEqual(default, key.GetClaim<Guid>(Claim.Sub));
        key.PutClaim(Claim.Sys, Commons.SystemName);
        Assert.IsNotNull(key.GetClaim<string>(Claim.Sys));
        key.PutClaim(Claim.Uid, Guid.NewGuid());
        Assert.IsNotNull(key.GetClaim<Guid>(Claim.Uid));
        Assert.AreNotEqual(default, key.GetClaim<Guid>(Claim.Uid));
        try { key.PutClaim(Claim.Cap, new List<KeyCapability>() { KeyCapability.Encrypt }); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { key.PutClaim(Claim.Key,Commons.IssuerKey.Secret); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { key.PutClaim(Claim.Lnk, new ItemLink(Commons.IssuerKey)); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { var pri = new Dictionary<string, object>(); pri["tag"] = Commons.Payload; key.PutClaim(Claim.Pri, pri); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { key.PutClaim(Claim.Mim, Commons.Mimetype); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well*/ }
        try { key.PutClaim(Claim.Pub, Commons.IssuerKey.Public); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest4() 
    {
        var key = Key.Generate(KeyCapability.Sign);
        key.Sign(Commons.IssuerKey);
        try { key.RemoveClaim(Claim.Iat); Assert.IsTrue(false, "Exception not thrown."); } catch (InvalidOperationException) { /* all is well */ }
        try { key.PutClaim(Claim.Exp, DateTime.UtcNow); } catch (InvalidOperationException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest5()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, Commons.Context);
        key.Sign(Commons.IssuerKey);
        key.Strip();
        key.RemoveClaim(Claim.Ctx);
        key.PutClaim(Claim.Exp, DateTime.UtcNow);
    }
    
    [TestMethod]
    public void KeyTest1()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        Assert.IsTrue(key.HasCapability(KeyCapability.Sign));
        Assert.IsFalse(key.HasCapability(KeyCapability.Exchange));
        Assert.IsNotNull(key.GetClaim<Guid>(Claim.Uid));
        Assert.IsNotNull(key.Public);
        Assert.IsNotNull(key.Secret);
    }

    [TestMethod]
    public void KeyTest2()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        Assert.IsTrue(key.HasCapability(KeyCapability.Exchange));
        Assert.IsFalse(key.HasCapability(KeyCapability.Sign));
        Assert.IsNotNull(key.GetClaim<Guid>(Claim.Uid));
        Assert.IsNotNull(key.Public);
        Assert.IsNotNull(key.Secret);
    }

    [TestMethod]
    public void ExportTest1()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var encoded = key.Export();
        Assert.IsNotNull(encoded);
        Assert.IsTrue(encoded.StartsWith($"{Envelope.ItemHeader}:{Key.ItemHeader}"));
        Assert.IsTrue(encoded.Split(".").Length == 2);
    }

    [TestMethod]
    public void ImportTest1()
    {
        const string encoded = "Di:KEY.eyJ1aWQiOiI3ZmE2OGU4OC02ZDVjLTQwMmItOThkOC1mZDg2NjQwY2Y0ZjIiLCJpYXQiOiIyMDIxLTEyLTAxVDIwOjUzOjIzLjM4MzczM1oiLCJrZXkiOiIyVERYZDlXVXR3dVliaTROaFNRRUhmTjg5QmhLVkNTQWVqUFpmRlFRZ1BxaVJadXNUTkdtcll0ZVEiLCJwdWIiOiIyVERYZG9OdXNiNXlWQXB6WTIzYXR1UTNzbUdiOExuZ0o0QVpYRWhpck1mQ0t5OHFkNEZwM1c5OHMifQ";
        var key = Item.Import<Key>(encoded);
        Assert.IsTrue(key.HasCapability(KeyCapability.Sign));
        Assert.AreEqual(new Guid("7fa68e88-6d5c-402b-98d8-fd86640cf4f2"), key.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(DateTime.Parse("2021-12-01T20:53:23.383733Z").ToUniversalTime(), key.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual("2TDXd9WUtwuYbi4NhSQEHfN89BhKVCSAejPZfFQQgPqiRZusTNGmrYteQ", key.Secret);
        Assert.AreEqual("2TDXdoNusb5yVApzY23atuQ3smGb8LngJ4AZXEhirMfCKy8qd4Fp3W98s", key.Public);
    }

    [TestMethod]
    public void PublicOnlyTest1()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, 120, Guid.NewGuid(), Commons.Context);
        Assert.IsNotNull(key.Secret);
        var pubOnly = key.PublicCopy();
        Assert.IsNull(pubOnly.Secret);
        Assert.AreEqual(key.Public, pubOnly.Public);
        Assert.AreEqual(key.GetClaim<Guid>(Claim.Uid), pubOnly.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(key.GetClaim<DateTime>(Claim.Iat), pubOnly.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(key.GetClaim<DateTime>(Claim.Exp), pubOnly.GetClaim<DateTime>(Claim.Exp));
        Assert.AreEqual(key.GetClaim<Guid>(Claim.Iss), pubOnly.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(key.GetClaim<string>(Claim.Ctx), pubOnly.GetClaim<string>(Claim.Ctx));
    }

    [TestMethod]
    public void PublicOnlyTest2()
    {
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 100L);
        message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
        message.Sign(Commons.IssuerKey);
        var pubOnly = Commons.IssuerKey.PublicCopy();
        message.Verify(pubOnly);            
    }
        
    [TestMethod]
    public void ContextTest1() {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, context);
        Assert.AreEqual(context, key.GetClaim<string>(Claim.Ctx));
    }

    [TestMethod]
    public void ContextTest2() {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        var key1 = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, context);
        var exported = key1.Export();
        var key2 = Item.Import<Key>(exported);
        Assert.AreEqual(context, key2.GetClaim<string>(Claim.Ctx));
    }

    [TestMethod]
    public void ContextTest3() 
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, context);
        } catch (ArgumentException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }
        
}