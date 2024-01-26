//
//  KeyTests.cs
//  DiME - Data Integrity Message Envelope
//  A powerful universal data format that is built for secure, and integrity protected communication between trusted
//  entities in a network.
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2024 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Collections.Generic;
using System.Text;
using DiME;
using DiME.Capability;
using DiME.KeyRing;

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
        key.PutClaim(Claim.Cmn, Commons.CommonName);
        Assert.IsNotNull(key.GetClaim<string>(Claim.Cmn));
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
        key.PutClaim(Claim.Isu, Commons.IssuerUrl);
        Assert.IsNotNull(key.GetClaim<string>(Claim.Isu));
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
    public void KeyCapabilityTest1() 
    {
        var signKey = Key.Generate(KeyCapability.Sign);
        Assert.AreEqual(Dime.Crypto.DefaultSuiteName, signKey.CryptoSuiteName);
        Assert.IsNotNull(signKey.Secret);
        Assert.IsNotNull(signKey.Public);
        var caps = signKey.Capabilities;
        Assert.IsNotNull(caps);
        Assert.IsTrue(caps.Contains(KeyCapability.Sign));
        Assert.AreEqual(1, caps.Count);
        Assert.IsTrue(signKey.HasCapability(KeyCapability.Sign));
        Assert.IsFalse(signKey.HasCapability(KeyCapability.Exchange));
        Assert.IsFalse(signKey.HasCapability(KeyCapability.Encrypt));
    }

    [TestMethod]
    public void KeyCapabilityTest2() 
    {
        var exchangeKey = Key.Generate(KeyCapability.Exchange);
        Assert.AreEqual(Dime.Crypto.DefaultSuiteName, exchangeKey.CryptoSuiteName);
        Assert.IsNotNull(exchangeKey.Secret);
        Assert.IsNotNull(exchangeKey.Public);
        var caps = exchangeKey.Capabilities;
        Assert.IsNotNull(caps);
        Assert.IsTrue(caps.Contains(KeyCapability.Exchange));
        Assert.AreEqual(1, caps.Count);
        Assert.IsFalse(exchangeKey.HasCapability(KeyCapability.Sign));
        Assert.IsTrue(exchangeKey.HasCapability(KeyCapability.Exchange));
        Assert.IsFalse(exchangeKey.HasCapability(KeyCapability.Encrypt));
    }

    [TestMethod]
    public void KeyCapabilityTest3() 
    {
        var encryptionKey = Key.Generate(KeyCapability.Encrypt);
        Assert.AreEqual(Dime.Crypto.DefaultSuiteName, encryptionKey.CryptoSuiteName);
        Assert.IsNotNull(encryptionKey.Secret);
        Assert.IsNull(encryptionKey.Public);
        var caps = encryptionKey.Capabilities;
        Assert.IsNotNull(caps);
        Assert.IsTrue(caps.Contains(KeyCapability.Encrypt));
        Assert.AreEqual(1, caps.Count);
        Assert.IsFalse(encryptionKey.HasCapability(KeyCapability.Sign));
        Assert.IsFalse(encryptionKey.HasCapability(KeyCapability.Exchange));
        Assert.IsTrue(encryptionKey.HasCapability(KeyCapability.Encrypt));
    }

    [TestMethod]
    public void KeyCapabilityTest4() 
    {
        var use = new List<KeyCapability>() { KeyCapability.Sign, KeyCapability.Exchange };
        try {
            Key.Generate(use, Dime.NoExpiration, null, null, Dime.Crypto.DefaultSuiteName);
            Assert.IsTrue(false, "Exception not thrown.");
        } catch (ArgumentException) { /* All is well good */ }
    }

    [TestMethod]
    public void KeyCapabilityTest5() 
    {
        var key1 = Key.Generate(KeyCapability.Sign);
        var exported1 = key1.Export();
        var key2 = Item.Import<Key>(exported1);
        Assert.IsNotNull(key2);
        Assert.IsTrue(key2.HasCapability(KeyCapability.Sign));
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
        const string encoded = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJpYXQiOiIyMDI0LTAxLTI2VDE1OjA5OjA5Ljk1NTYyNTVaIiwia2V5IjoiTmFDbC5PcDN3Yk0zaFNsdS93eXFFZkp2bDJhTHNBdGpQWmE4aVlYWUpvejhhY0pUUVoyTFkyZkhhL2VvQlVPRFhzaThzdFY1K1B4dHVYL29nTEh1ZUFQMDRrUSIsInB1YiI6Ik5hQ2wuMEdkaTJObngydjNxQVZEZzE3SXZMTFZlZmo4YmJsLzZJQ3g3bmdEOU9KRSIsInVpZCI6IjRiOTQxZWE0LTFjMmItNDBjZi1iYjMwLWIzZmE3N2ZkMDNhMCJ9";
        var key = Item.Import<Key>(encoded);
        Assert.AreEqual(1, key.Capabilities.Count);
        Assert.IsTrue(key.HasCapability(KeyCapability.Sign));
        Assert.AreEqual(new Guid("4b941ea4-1c2b-40cf-bb30-b3fa77fd03a0"), key.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(DateTime.Parse("2024-01-26T15:09:09.9556255Z").ToUniversalTime(), key.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual("NaCl.Op3wbM3hSlu/wyqEfJvl2aLsAtjPZa8iYXYJoz8acJTQZ2LY2fHa/eoBUODXsi8stV5+PxtuX/ogLHueAP04kQ", key.Secret);
        Assert.AreEqual("NaCl.0Gdi2Nnx2v3qAVDg17IvLLVefj8bbl/6ICx7ngD9OJE", key.Public);
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
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
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
    
    [TestMethod]
    public void StripTest1() 
    {
        var key = Key.Generate(KeyCapability.Encrypt);
        key.Sign(Commons.IssuerKey);
        key.Sign(Commons.AudienceKey);
        Assert.AreEqual(IntegrityState.Complete, key.Verify(Commons.IssuerKey));
        Assert.AreEqual(IntegrityState.Complete, key.Verify(Commons.AudienceKey));
        Assert.IsTrue(key.Strip(Commons.AudienceKey));
        Assert.AreEqual(IntegrityState.Complete, key.Verify(Commons.IssuerKey));
        Assert.AreEqual(IntegrityState.FailedKeyMismatch, key.Verify(Commons.AudienceKey));
        Assert.IsFalse(key.Strip(Commons.AudienceKey));
    }

    [TestMethod]
    public void CommonNameTest1()
    {
        var key = Key.Generate(KeyCapability.Sign);
        key.PutClaim(Claim.Cmn, Commons.CommonName);
        Assert.IsNotNull(key.GetClaim<string>(Claim.Cmn));
        Assert.AreEqual(Commons.CommonName, key.GetClaim<string>(Claim.Cmn));
    }

    [TestMethod]
    public void CommonNameTest2()
    {
        const string exported = "Di:KEY.eyJjYXAiOlsic2lnbiJdLCJjbW4iOiJEaU1FIiwiaWF0IjoiMjAyNC0wMS0yNlQxNzoyODowNi4xOTY0MzRaIiwia2V5IjoiTmFDbC5GVjNOM3crSXAxeHY3OHZ2L3JrWUJibzQyZElGVnZ6cTN3SGo1cUZTazVjcXpiTStrbEFuYTZjalV3bURpeVRyc2FJdWY2MmFHNWFuNFArd1FrV0h5QSIsInB1YiI6Ik5hQ2wuS3MyelBwSlFKMnVuSTFNSmc0c2s2N0dpTG4rdG1odVdwK0Qvc0VKRmg4ZyIsInVpZCI6ImZjZDNkMzI2LWY2NzQtNGQyZi1iODFhLTA3NWZlYmIwYTFkNSJ9";
        var key = Item.Import<Key>(exported);
        Assert.IsNotNull(key.GetClaim<string>(Claim.Cmn));
        Assert.AreEqual(Commons.CommonName, key.GetClaim<string>(Claim.Cmn));
    }

}