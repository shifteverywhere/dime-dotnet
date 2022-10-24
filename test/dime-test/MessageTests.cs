//
//  MessageTests.cs
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
using System.Threading;
using DiME;
using DiME.Capability;

namespace DiME_test;

[TestClass]
public class MessageTests
{
    
    [TestMethod]
    public void GetHeaderTest1() 
    {
        var msg = new Message();
        Assert.AreEqual("MSG", msg.Header);
        Assert.AreEqual("MSG", Message.ItemHeader);
    }
    
    [TestMethod]
    public void ClaimTest1() 
    {
        var message = new Message(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        Assert.IsNotNull(message.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), message.GetClaim<Guid>(Claim.Iss));
    }

    [TestMethod]
    public void ClaimTest2() 
    {
        var message = new Message(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), Commons.Mimetype);
        Assert.IsNotNull(message.GetClaim<string>(Claim.Mim));
        Assert.AreEqual(Commons.Mimetype, message.GetClaim<string>(Claim.Mim));
        message.RemoveClaim(Claim.Mim);
        Assert.AreEqual(default, message.GetClaim<string>(Claim.Mim));
    }

    [TestMethod]
    public void ClaimTest3() 
    {
        var message = new Message(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.PutClaim(Claim.Amb, new List<string>() { "one", "two" });
        Assert.IsNotNull(message.GetClaim<List<string>>(Claim.Amb));
        message.PutClaim(Claim.Aud, Guid.NewGuid());
        Assert.IsNotNull(message.GetClaim<Guid>(Claim.Aud));
        Assert.AreNotEqual(default, message.GetClaim<Guid>(Claim.Aud));
        message.PutClaim(Claim.Ctx, Commons.Context);
        Assert.IsNotNull(message.GetClaim<string>(Claim.Ctx));
        message.PutClaim(Claim.Exp, DateTime.UtcNow);
        Assert.IsNotNull(message.GetClaim<DateTime>(Claim.Exp));
        Assert.AreNotEqual(default, message.GetClaim<DateTime>(Claim.Exp));
        message.PutClaim(Claim.Iat, DateTime.UtcNow);
        Assert.IsNotNull(message.GetClaim<DateTime>(Claim.Iat));
        Assert.AreNotEqual(default, message.GetClaim<DateTime>(Claim.Iat));
        message.PutClaim(Claim.Iss, Guid.NewGuid());
        Assert.IsNotNull(message.GetClaim<Guid>(Claim.Iss));
        Assert.AreNotEqual(default, message.GetClaim<Guid>(Claim.Iss));
        message.PutClaim(Claim.Kid, Guid.NewGuid());
        Assert.IsNotNull(message.GetClaim<Guid>(Claim.Kid));
        Assert.AreNotEqual(default, message.GetClaim<Guid>(Claim.Kid));
        message.PutClaim(Claim.Mim, Commons.Mimetype);
        Assert.IsNotNull(message.GetClaim<string>(Claim.Mim));
        message.PutClaim(Claim.Mtd, new List<string>() { "abc", "def" });
        Assert.IsNotNull(message.GetClaim<List<string>>(Claim.Mtd));
        message.PutClaim(Claim.Sub, Guid.NewGuid());
        Assert.IsNotNull(message.GetClaim<Guid>(Claim.Sub));
        Assert.AreNotEqual(default, message.GetClaim<Guid>(Claim.Sub));
        message.PutClaim(Claim.Sys, Commons.SystemName);
        Assert.IsNotNull(message.GetClaim<string>(Claim.Sys));
        message.PutClaim(Claim.Uid, Guid.NewGuid());
        Assert.IsNotNull(message.GetClaim<Guid>(Claim.Uid));
        Assert.AreNotEqual(default, message.GetClaim<Guid>(Claim.Uid));
        try { message.PutClaim(Claim.Cap, new List<KeyCapability>() { KeyCapability.Encrypt }); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { message.PutClaim(Claim.Key,Commons.IssuerKey.Secret); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { message.PutClaim(Claim.Lnk, new ItemLink(Commons.IssuerKey)); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { var pri = new Dictionary<string, object>(); pri["tag"] = Commons.Payload; message.PutClaim(Claim.Pri, pri); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
        try { message.PutClaim(Claim.Pub, Commons.IssuerKey.Public); Assert.IsTrue(false, "Exception not thrown."); } catch (ArgumentException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest4() 
    {
        var message = new Message(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        try { message.RemoveClaim(Claim.Iss); Assert.IsTrue(false, "Exception not thrown."); } catch (InvalidOperationException) { /* all is well */ }
        try { message.PutClaim(Claim.Exp, DateTime.UtcNow); } catch (InvalidOperationException) { /* all is well */ }
    }

    [TestMethod]
    public void ClaimTest5() 
    {
        var message = new Message(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        message.Strip();
        message.RemoveClaim(Claim.Iss);
        message.PutClaim(Claim.Iat, DateTime.UtcNow);
    }

    [TestMethod]
    public void MessageTest1()
    {
        Commons.InitializeKeyRing();
        var now = DateTime.UtcNow;
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        Assert.IsNotNull(message.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), message.GetClaim<Guid>(Claim.Aud));
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload()));
        Assert.IsTrue(message.GetClaim<DateTime>(Claim.Iat) >= now && message.GetClaim<DateTime>(Claim.Iat) <= (now.AddSeconds(1)));
        Assert.IsTrue(message.GetClaim<DateTime>(Claim.Exp) > (now.AddSeconds(9)) && message.GetClaim<DateTime>(Claim.Exp) < (now.AddSeconds(11)));
    }

    [TestMethod]
    public void MessageTest2()
    {
        Commons.InitializeKeyRing();
        var payload = Encoding.UTF8.GetBytes(Commons.Payload);
        const long validFor = 10L;
        var message1 = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), validFor);
        message1.SetPayload(payload);
        var message2 = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), validFor);
        message2.SetPayload(payload);
        Assert.AreNotEqual(message1.GetClaim<Guid>(Claim.Uid), message2.GetClaim<Guid>(Claim.Uid));
    }

    [TestMethod]
    public void MessageTest3()
    {
        Commons.InitializeKeyRing();
        const string text = Commons.Payload;
        var payload = Encoding.UTF8.GetBytes(text);
        var message1 = new Message(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        message1.SetPayload(payload);
        Assert.AreEqual(default(Guid), message1.GetClaim<Guid>(Claim.Aud));
        message1.Sign(Commons.IssuerKey);
        var message2 = Item.Import<Message>(message1.Export());
        Assert.AreEqual(default(Guid), message2.GetClaim<Guid>(Claim.Aud));
        Assert.AreEqual(text, Encoding.UTF8.GetString(message2.GetPayload()));
    }

    [TestMethod]
    public void ExportTest1()
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        var encoded = message.Export();
        Assert.IsNotNull(encoded);
        Assert.IsTrue(encoded.Length > 0);
        Assert.IsTrue(encoded.StartsWith($"{Envelope.ItemHeader}:{Message.ItemHeader}"));
        Assert.IsTrue(encoded.Split(new[] {'.'}).Length == 4);
    }

    [TestMethod]
    public void ExportTest2()
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 10L);
        try
        {
            message.Export();
        }
        catch (InvalidOperationException)
        {
            return;
        } // All is well

        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void ExportTest3()
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        Assert.AreEqual(message.Export(), message.Export());
    }

    [TestMethod]
    public void VerifyTest1()
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), -10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        Assert.IsFalse(Dime.IsIntegrityStateValid(message.Verify(Commons.IssuerKey)));
    }

    [TestMethod]
    public void VerifyTest2()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var untrustedSender = IdentityIssuingRequest.Generate(key)
            .SelfIssue(Guid.NewGuid(), 120L, key, Commons.SystemName);
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), untrustedSender.GetClaim<Guid>(Claim.Sub), 120L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(key);
        Assert.IsFalse(Dime.IsIntegrityStateValid(message.Verify(Commons.IssuerKey)));
    }

    [TestMethod]
    public void VerifyTest3()
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 120L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        message.Verify(Commons.IssuerIdentity.PublicKey);
    }

    [TestMethod]
    public void VerifyTest4()
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        message.Verify(Commons.IssuerIdentity.PublicKey);
    } 
        
    [TestMethod] 
    public void VerifyTest5() 
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub),1L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        Thread.Sleep(1000);
        Assert.IsFalse(Dime.IsIntegrityStateValid(message.Verify(Commons.IssuerIdentity.PublicKey)));
        Dime.GracePeriod = 1L;
        message.Verify(Commons.IssuerIdentity.PublicKey);
        Dime.GracePeriod = 0L;
    }
    
    [TestMethod]
    public void VerifyTest6() 
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub),1L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        Thread.Sleep(2000);
        Dime.TimeModifier = -2L;
        message.Verify(Commons.IssuerIdentity.PublicKey);
    }

    [TestMethod]
    public void VerifyTest7() 
    {
        Dime.TimeModifier = -2;
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 1L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        Thread.Sleep(2000);
        Assert.IsFalse(Dime.IsIntegrityStateValid(message.Verify(Commons.IssuerIdentity.PublicKey)));
    }
    
    [TestMethod]
    public void ImportTest1()
    {
        Commons.InitializeKeyRing();
        const string exported =
            "Di:MSG.eyJhdWQiOiI5ZDBjNmMwMy01ZTVmLTQ0Y2ItYjFlZi1iMzA0MDNlNTA2ZjAiLCJleHAiOiIyMDIyLTEwLTI0VDIyOjQ5OjMyLjA4NzIxMloiLCJpYXQiOiIyMDIyLTEwLTI0VDIyOjQ5OjIyLjA4NzIxMloiLCJpc3MiOiIxMDMwNTcyZi02YjgyLTQzNmQtOWQ1MS03OTAyMGU2MmY4NTMiLCJ1aWQiOiJhODk1YTM3NS0yZmI0LTQ2NDItODUxMi04NzM3MmE1OWU0ZmYifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.YzFmMjczMDUzZDhmZDQ4YS44YjIyY2U2OTdmZmM2NTc0MWM4YjFmYjBmNTc3ODNkNmE0ZTJhZDM2ZjY4YjE1YjFkNjkzNmRhMTM0MDIyNzE5MTVhNDc0ZmRjYjk3NGYzMmE3MDNlMzVlZGUzMDI3ODViZDQzNTk2ODA1ZDYyYTE3NzljYWQxYmY1ZDFmMzAwMg";
        var message = Item.Import<Message>(exported);
        Assert.AreEqual(new Guid("a895a375-2fb4-4642-8512-87372a59e4ff"), message.GetClaim<Guid>(Claim.Uid));
        Assert.AreEqual(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), message.GetClaim<Guid>(Claim.Aud));
        Assert.AreEqual(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), message.GetClaim<Guid>(Claim.Iss));
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload()));
        Assert.AreEqual(DateTime.Parse("2022-10-24T22:49:22.087212Z").ToUniversalTime(), message.GetClaim<DateTime>(Claim.Iat));
        Assert.AreEqual(DateTime.Parse("2022-10-24T22:49:32.087212Z").ToUniversalTime(), message.GetClaim<DateTime>(Claim.Exp));
        Assert.AreEqual(message.GetClaim<Guid>(Claim.Iss), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
    }

    [TestMethod]
    public void ImportTest2()
    {
        Commons.InitializeKeyRing();
        const string encoded =
            "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiI1ZWRkMmFkZS1mZjRiLTQ1YzktODMyMy1iOTE4YWJmYWZkMjEiLCJzdWIiOiJiMzIyNTU3NC1jYTNkLTRlYWItODNlMC03NjU1MDE2ZWEyMmQiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjE5NzU2MzAsImV4cCI6MTYyMTk3NTY0MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
        try
        {
            _ = Item.Import<Message>(encoded);
            Assert.IsTrue(false, "Exception not thrown.");
        }
        catch (FormatException)
        {
            /* all is well */
        }
    }

    [TestMethod]
    public void ImportTest3()
    {
        var message1 = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 120L);
        message1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message1.Sign(Commons.IssuerKey);
        var encoded = message1.Export();
        var message2 = Item.Import<Message>(encoded);
        message2.Verify(Commons.IssuerKey);
    }

    [TestMethod]
    public void SignTest1()
    {  
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 10L);
        try {
            message.Sign(Commons.IssuerKey);
        } catch (InvalidOperationException) { return; } // All is well
        Assert.IsTrue(false, Commons.Payload);
    }

    [TestMethod]
    public void SignTest2()
    {  
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        try { message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload)); Assert.IsTrue(false, "Exception not thrown."); } catch (InvalidOperationException) { /* all is well */ }
    }
    
    [TestMethod]
    public void SignTest3() 
    {
        // Multiple signatures
        var key1 = Key.Generate(KeyCapability.Sign);
        var key2 = Key.Generate(KeyCapability.Sign);
        var key3 = Key.Generate(KeyCapability.Sign);
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(key1);
        Assert.IsTrue(Dime.IsIntegrityStateValid(message.Verify(key1)));
        message.Sign(key2);
        Assert.IsTrue(Dime.IsIntegrityStateValid(message.Verify(key1)));
        Assert.IsTrue(Dime.IsIntegrityStateValid(message.Verify(key2)));
        Assert.IsFalse(Dime.IsIntegrityStateValid(message.Verify(key3)));
    }

    [TestMethod]
    public void IsSignedTest1()
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        Assert.IsFalse(message.IsSigned);
        message.Sign(Commons.IssuerKey);
        Assert.IsTrue(message.IsSigned);
    }
        
    [TestMethod]
    public void SetPayloadTest1()
    {
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 100L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload()));
    }

    [TestMethod]
    public void SetPayloadTest2()
    {
        var message1 = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 100L);
        message1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message1.GetPayload()));
        message1.Sign(Commons.IssuerKey);
        var message2 = Item.Import<Message>(message1.Export());
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message2.GetPayload()));
    }

    [TestMethod]
    public void SetPayloadTest3()
    {
        var localKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var remoteKey =Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null).PublicCopy();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), 100L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), localKey, remoteKey);
        Assert.AreNotEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload()));
    }

    [TestMethod]
    public void SetPayloadTest4()
    {
        var issuerKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var audienceKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub),
            Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        message.PutClaim(Claim.Kid, issuerKey.GetClaim<Guid>(Claim.Uid));
        message.PublicKey = audienceKey.PublicCopy();
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), issuerKey, audienceKey.PublicCopy());
        Assert.AreEqual(issuerKey.GetClaim<Guid>(Claim.Uid), message.GetClaim<Guid>(Claim.Kid));
        Assert.IsNotNull(message.PublicKey);
        Assert.AreEqual(audienceKey.Public, message.PublicKey.Public);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload(issuerKey.PublicCopy(), audienceKey)));
    }

    [TestMethod]
    public void SetPayloadTest5()
    {
        var issuerKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var audienceKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var message1 = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        message1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), issuerKey, audienceKey.PublicCopy());
        message1.Sign(Commons.IssuerKey);
        var message2 = Item.Import<Message>(message1.Export());
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message2.GetPayload(issuerKey.PublicCopy(), audienceKey)));
    }

    [TestMethod]
    public void SetPayloadTest6()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        try {
            message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), key, key);
        } catch (ArgumentException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void LinkItemTest1()
    {
        Commons.InitializeKeyRing();
        var issuer = Commons.IssuerIdentity;
        var receiver = Commons.AudienceIdentity;
        var issuerMessage = new Message(receiver.GetClaim<Guid>(Claim.Sub), issuer.GetClaim<Guid>(Claim.Sub), 100L);
        issuerMessage.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        issuerMessage.Sign(Commons.IssuerKey);
            
        var issuerEncoded = issuerMessage.Export();
        var receivedMessage = Item.Import<Message>(issuerEncoded);
        var responseMessage = new Message(issuer.GetClaim<Guid>(Claim.Sub), receiver.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        responseMessage.SetPayload(Encoding.UTF8.GetBytes("It is!"));
        responseMessage.AddItemLink(receivedMessage);
        responseMessage.Sign(Commons.AudienceKey);
        var responseEncoded = responseMessage.Export();
        var finalMessage = Item.Import<Message>(responseEncoded);
        finalMessage.Verify(Commons.AudienceKey, new List<Item>() { receivedMessage });
    }

    [TestMethod]
    public void LinkItemTest2()
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.AddItemLink(Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null));
        message.Sign(Commons.IssuerKey);
        Assert.IsFalse(Dime.IsIntegrityStateValid(message.Verify(Commons.IssuerKey, new List<Item>() { Commons.IssuerKey })));
    }
        
    [TestMethod]
    public void LinkItemTest3()
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        try {
            message.AddItemLink(Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null));
        } catch (InvalidOperationException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }
    
    [TestMethod]
    public void LinkItemTest4() 
    {
        Commons.InitializeKeyRing();
        var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        message.SetItemLinks(new List<Item>() { Commons.AudienceIdentity, Commons.IssuerIdentity });
        var itemLinks = message.GetItemLinks();
        Assert.IsNotNull(itemLinks);
        Assert.AreEqual(2, itemLinks.Count);
        message.RemoveLinkItems();
        Assert.IsNull(message.GetItemLinks());
    }

    [TestMethod]
    public void ThumbprintTest1()
    {
        Commons.InitializeKeyRing();
        var message1 = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        message1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message1.Sign(Commons.IssuerKey);
        var thumbprint1 = message1.GenerateThumbprint();
        var encoded = message1.Export();
        var message2 = Item.Import<Message>(encoded);
        var thumbprint2 = message2.GenerateThumbprint();
        Assert.AreEqual(thumbprint1, thumbprint2);
    }

    [TestMethod]
    public void ThumbprintTest2()
    {
        Commons.InitializeKeyRing();
        var issuer = Commons.IssuerIdentity;
        var receiver = Commons.AudienceIdentity;
        var issuerMessage1 = new Message(receiver.GetClaim<Guid>(Claim.Sub), issuer.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        issuerMessage1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        issuerMessage1.Sign(Commons.IssuerKey);
        var issuerMessage2 = new Message(receiver.GetClaim<Guid>(Claim.Sub), issuer.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
        issuerMessage2.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        issuerMessage2.Sign(Commons.IssuerKey);
        Assert.AreNotEqual(issuerMessage1.GenerateThumbprint(), issuerMessage2.GenerateThumbprint());
    }
    
    [TestMethod]
    public void ThumbprintTest3() 
    {
        try {
            var message = new Message(Commons.AudienceIdentity.GetClaim<Guid>(Claim.Sub), Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub), Dime.ValidFor1Minute);
            message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
            message.GenerateThumbprint();
            Assert.IsTrue(false, "Exception not thrown.");
        } catch (InvalidOperationException) {
            /* All is well */
        }
    }
    
    [TestMethod]
    public void ContextTest1() 
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Assert.IsNotNull(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Iss));
        var message = new Message(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Iss), Dime.NoExpiration, context);
        Assert.AreEqual(context, message.GetClaim<string>(Claim.Ctx));
    }

    [TestMethod]
    public void ContextTest2() 
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Assert.IsNotNull(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Iss));
        var message1 = new Message(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Iss), Dime.NoExpiration, context);
        message1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message1.Sign(Commons.IssuerKey);
        var message2 = Item.Import<Message>(message1.Export());
        Assert.AreEqual(context, message2.GetClaim<string>(Claim.Ctx));
    }

    [TestMethod]
    public void ContextTest3() 
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            Assert.IsNotNull(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Iss));
            _ = new Message(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Iss), Dime.NoExpiration, context);
        } catch (ArgumentException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }
    
    [TestMethod]
    public void StripTest1() 
    {
        var message = new Message(Commons.IssuerIdentity.GetClaim<Guid>(Claim.Sub));
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        try {
            message.PublicKey = Commons.IssuerKey.PublicCopy();
            Assert.IsTrue(false, "Expected not thrown.");
        } catch (InvalidOperationException) {
            /* all is well */
        }
        message.Strip();
        message.Sign(Commons.IssuerKey);
    }
 
}