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
using DiME.Exceptions;

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
    public void GetTagTest1()
    {
        var message = new Message(Guid.NewGuid());
        Assert.AreEqual("MSG", message.Header);
    }

    [TestMethod]
    public void MessageTest1()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var now = DateTime.UtcNow;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        Assert.IsNotNull(message.UniqueId);
        Assert.AreEqual(Commons.AudienceIdentity.SubjectId, message.AudienceId);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload()));
        Assert.IsTrue(message.IssuedAt >= now && message.IssuedAt <= (now.AddSeconds(1)));
        Assert.IsTrue(message.ExpiresAt > (now.AddSeconds(9)) && message.ExpiresAt < (now.AddSeconds(11)));
    }

    [TestMethod]
    public void MessageTest2()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var payload = Encoding.UTF8.GetBytes(Commons.Payload);
        const long validFor = 10L;
        var message1 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, validFor);
        message1.SetPayload(payload);
        var message2 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, validFor);
        message2.SetPayload(payload);
        Assert.AreNotEqual(message1.UniqueId, message2.UniqueId);
    }

    [TestMethod]
    public void MessageTest3()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        const string text = Commons.Payload;
        var payload = Encoding.UTF8.GetBytes(text);
        var message1 = new Message(Commons.IssuerIdentity.SubjectId);
        message1.SetPayload(payload);
        Assert.IsNull(message1.AudienceId);
        message1.Sign(Commons.IssuerKey);
        var message2 = Item.Import<Message>(message1.Export());
        Assert.IsNull(message2.AudienceId);
        Assert.AreEqual(text, Encoding.UTF8.GetString(message2.GetPayload()));
    }

    [TestMethod]
    public void ExportTest1()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10L);
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
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10L);
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
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        Assert.AreEqual(message.Export(), message.Export());
    }

    [TestMethod]
    public void VerifyTest1()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, -10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        try
        {
            message.Verify(Commons.IssuerKey);
        }
        catch (DateExpirationException)
        {
            return;
        } // All is well

        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void VerifyTest2()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var untrustedSender = IdentityIssuingRequest.Generate(key)
            .SelfIssue(Guid.NewGuid(), 120L, key, Commons.SystemName);
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, untrustedSender.SubjectId, 120L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(key);
        try
        {
            message.Verify(Commons.IssuerKey);
        }
        catch (IntegrityException)
        {
            return;
        } // All is well

        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void VerifyTest3()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 120L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        message.Verify(Commons.IssuerIdentity.PublicKey);
    }

    [TestMethod]
    public void VerifyTest4()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        message.Verify(Commons.IssuerIdentity.PublicKey);
    } 
        
    [TestMethod] 
    public void VerifyTest5() 
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId,1L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        Thread.Sleep(1000);
        try { message.Verify(Commons.IssuerIdentity.PublicKey); Assert.IsTrue(false, "Exception not thrown."); } catch (DateExpirationException) { /* all is well */ }
        Dime.GracePeriod = 1L;
        message.Verify(Commons.IssuerIdentity.PublicKey);
        Dime.GracePeriod = 0L;
    }


    [TestMethod]
    public void VerifyTest6() 
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId,1L);
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
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 1L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        Thread.Sleep(2000);
        try { message.Verify(Commons.IssuerIdentity.PublicKey); Assert.IsTrue(false, "Exception not thrown."); } catch (DateExpirationException) { /* all is well */ }
    }
    
    [TestMethod]
    public void ImportTest1()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        const string exported =
            "Di:MSG.eyJhdWQiOiI4ZmRkYzI0Mi02NzBlLTRjNzMtODRiZS04Mjc2MWEzOTI3ZWYiLCJleHAiOiIyMDIyLTEwLTE3VDE5OjA0OjMyLjExODI3MloiLCJpYXQiOiIyMDIyLTEwLTE3VDE5OjA0OjIyLjExODI3MloiLCJpc3MiOiIzYjAxZDcyMi1lNjZiLTQ2ODMtYTViNi05M2RjNmU2MGUwMTciLCJ1aWQiOiIxNzlhMzU4OC0wNGZjLTQ4MWUtODdlOS0xY2NmNjNlMGM5NDAifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.MzFhMDYyN2JlZjk1NjNiZC4wM2E1ZmYxYjZjMzE3NWJkNTcwODgxZjZjYzczZGUwZTQ3MzhlNTEwNGI5YTQyYmM4YzhkYTJjMzFhNjQ5N2FlZGZhMGE2YjQzOGRlYjU5Yzg3YjIzODNiYjU5NDcyMzMxZWVjM2YyMzg2ZWY3ZTI2YmRmNGRkZDJmNmM2NTUwMQ";
        var message = Item.Import<Message>(exported);
        Assert.AreEqual(new Guid("179a3588-04fc-481e-87e9-1ccf63e0c940"), message.UniqueId);
        Assert.AreEqual(Commons.AudienceIdentity.SubjectId, message.AudienceId);
        Assert.AreEqual(Commons.IssuerIdentity.SubjectId, message.IssuerId);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload()));
        Assert.AreEqual(DateTime.Parse("2022-10-17T19:04:22.118272Z").ToUniversalTime(), message.IssuedAt);
        Assert.AreEqual(DateTime.Parse("2022-10-17T19:04:32.118272Z").ToUniversalTime(), message.ExpiresAt);
        Assert.AreEqual(message.IssuerId, Commons.IssuerIdentity.SubjectId);
    }

    [TestMethod]
    public void ImportTest2()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        const string encoded =
            "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiI1ZWRkMmFkZS1mZjRiLTQ1YzktODMyMy1iOTE4YWJmYWZkMjEiLCJzdWIiOiJiMzIyNTU3NC1jYTNkLTRlYWItODNlMC03NjU1MDE2ZWEyMmQiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjE5NzU2MzAsImV4cCI6MTYyMTk3NTY0MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
        try
        {
            _ = Item.Import<Message>(encoded);
        }
        catch (FormatException)
        {
            return;
        } // All is well

        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void ImportTest3()
    {
        var message1 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 120L);
        message1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message1.Sign(Commons.IssuerKey);
        var encoded = message1.Export();
        var message2 = Item.Import<Message>(encoded);
        message2.Verify(Commons.IssuerKey);
    }

    [TestMethod]
    public void SignTest1()
    {  
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10L);
        try {
            message.Sign(Commons.IssuerKey);
        } catch (InvalidOperationException) { return; } // All is well
        Assert.IsTrue(false, Commons.Payload);
    }

    [TestMethod]
    public void SignTest2()
    {  
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        try {
            message.KeyId = Guid.NewGuid();
            message.PublicKey = Commons.IssuerKey.Public;
        } catch (InvalidOperationException) { return; } // All is well
        Assert.IsTrue(false, Commons.Payload);
    }

    [TestMethod]
    public void IsSignedTest1()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        Assert.IsFalse(message.IsSigned);
        message.Sign(Commons.IssuerKey);
        Assert.IsTrue(message.IsSigned);
    }
        
    [TestMethod]
    public void SetPayloadTest1()
    {
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload()));
    }

    [TestMethod]
    public void SetPayloadTest2()
    {
        var message1 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L);
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
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), localKey, remoteKey);
        Assert.AreNotEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload()));
    }

    [TestMethod]
    public void SetPayloadTest4()
    {
        var issuerKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var audienceKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L)
        {
            KeyId = issuerKey.UniqueId,
            PublicKey = audienceKey.Public
        };
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), issuerKey, audienceKey.PublicCopy());
        Assert.AreEqual(issuerKey.UniqueId, message.KeyId);
        Assert.AreEqual(audienceKey.Public, message.PublicKey);
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message.GetPayload(issuerKey.PublicCopy(), audienceKey)));
    }

    [TestMethod]
    public void SetPayloadTest5()
    {
        var issuerKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var audienceKey = Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null);
        var message1 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L);
        message1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), issuerKey, audienceKey.PublicCopy());
        message1.Sign(Commons.IssuerKey);
        var message2 = Item.Import<Message>(message1.Export());
        Assert.AreEqual(Commons.Payload, Encoding.UTF8.GetString(message2.GetPayload(issuerKey.PublicCopy(), audienceKey)));
    }

    [TestMethod]
    public void SetPayloadTest6()
    {
        var key = Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null);
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L);
        try {
            message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload), key, key);
        } catch (ArgumentException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void LinkItemTest1()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var issuer = Commons.IssuerIdentity;
        var receiver = Commons.AudienceIdentity;
        var issuerMessage = new Message(receiver.SubjectId, issuer.SubjectId, 100L);
        issuerMessage.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        issuerMessage.Sign(Commons.IssuerKey);
            
        var issuerEncoded = issuerMessage.Export();
        var receivedMessage = Item.Import<Message>(issuerEncoded);
        var responseMessage = new Message(issuer.SubjectId, receiver.SubjectId, 100L);
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
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.AddItemLink(Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null));
        message.Sign(Commons.IssuerKey);
        try {
            message.Verify(Commons.IssuerKey, new List<Item>() { Commons.IssuerKey });
        } catch (IntegrityException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }
        
    [TestMethod]
    public void LinkItemTest3()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L);
        message.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message.Sign(Commons.IssuerKey);
        try {
            message.LinkItem(Key.Generate(new List<KeyCapability>() {KeyCapability.Exchange}, null));
        } catch (InvalidOperationException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }

    [TestMethod]
    public void ThumbprintTest1()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var message1 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100L);
        message1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message1.Sign(Commons.IssuerKey);
        var thumbprint1 = message1.Thumbprint();
        var encoded = message1.Export();
        var message2 = Item.Import<Message>(encoded);
        var thumbprint2 = message2.Thumbprint();
        Assert.AreEqual(thumbprint1, thumbprint2);
    }

    [TestMethod]
    public void ThumbprintTest2()
    {
        Dime.TrustedIdentity = Commons.TrustedIdentity;
        var issuer = Commons.IssuerIdentity;
        var receiver = Commons.AudienceIdentity;
        var issuerMessage1 = new Message(receiver.SubjectId, issuer.SubjectId, 100);
        issuerMessage1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        issuerMessage1.Sign(Commons.IssuerKey);
        var issuerMessage2 = new Message(receiver.SubjectId, issuer.SubjectId, 100);
        issuerMessage2.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        issuerMessage2.Sign(Commons.IssuerKey);
        Assert.AreNotEqual(issuerMessage1.Thumbprint(), issuerMessage2.Thumbprint());
    }
 

    [TestMethod]
    public void ContextTest1() 
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Assert.IsNotNull(Commons.IssuerIdentity.IssuerId);
        var message = new Message(Commons.IssuerIdentity.IssuerId.Value, -1, context);
        Assert.AreEqual(context, message.Context);
    }

    [TestMethod]
    public void ContextTest2() 
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234";
        Assert.IsNotNull(Commons.IssuerIdentity.IssuerId);
        var message1 = new Message(Commons.IssuerIdentity.IssuerId.Value, -1, context);
        message1.SetPayload(Encoding.UTF8.GetBytes(Commons.Payload));
        message1.Sign(Commons.IssuerKey);
        var message2 = Item.Import<Message>(message1.Export());
        Assert.AreEqual(context, message2.Context);
    }

    [TestMethod]
    public void ContextTest3() 
    {
        const string context = "123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890";
        try {
            Assert.IsNotNull(Commons.IssuerIdentity.IssuerId);
            _ = new Message(Commons.IssuerIdentity.IssuerId.Value, -1, context);
        } catch (ArgumentException) { return; } // All is well
        Assert.IsTrue(false, "Should not happen.");
    }
        
    [TestMethod]
    public void AlienMessageEncryptionTest1() 
    {
        const string text = Commons.Payload;
        var clientKey = Item.Import<Key>("Di:KEY.eyJ1aWQiOiIzOWYxMzkzMC0yYTJhLTQzOWEtYjBkNC1lMzJkMzc4ZDgyYzciLCJwdWIiOiIyREJWdG5NWlVjb0dZdHd3dmtjYnZBSzZ0Um1zOUZwNGJ4dHBlcWdha041akRVYkxvOXdueWRCUG8iLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0LjQ0NDA0MVoiLCJrZXkiOiIyREJWdDhWOEF4UWR4UFZVRkJKOWdScFA1WDQzNnhMbVBrWW9RNzE1cTFRd2ZFVml1NFM3RExza20ifQ");
        var serverKey = Item.Import<Key>("Di:KEY.eyJ1aWQiOiJjY2U1ZDU1Yi01NDI4LTRhMDUtOTZmYi1jZmU4ZTE4YmM3NWIiLCJwdWIiOiIyREJWdG5NYTZrcjNWbWNOcXNMSmRQMW90ZGtUMXlIMTZlMjV0QlJiY3pNaDFlc3J3a2hqYTdaWlEiLCJpYXQiOiIyMDIyLTA2LTAzVDEwOjUzOjM0Ljg0NjEyMVoiLCJrZXkiOiIyREJWdDhWOTV5N2lvb1A0bmRDajd6d3dqNW1MVExydVhaaGg0RTJuMUE0SHoxQkIycHB5WXY1blIifQ");
        // This is received by the client //
        var message = Item.Import<Message>("Di:MSG.eyJpc3MiOiIzOTA3MWIyNC04MGRmLTQyYzEtYWQwZS1jNmQ2ZmNmMjg5YmIiLCJ1aWQiOiJjNjExOWYxMC0wZDE3LTQ3NTItYTkwZS1lODlhOGI2OGIyY2MiLCJpYXQiOiIyMDIyLTA2LTAzVDEzOjU0OjM2Ljg4MDM3MVoifQ.8sdEJ3CuHLaA/DmYcCce+8iflhQwESkDwIF8xu69R4h6Pvt+k6HfDJjK+sYm4goKoA04hb8Zaq9wMGiuxXoqqBHAGqd/.WorEis9t8WdQiOW+yK2F8gLfBfrnlFk/W7FMmjBhPWpp7SAddq2UPvE0nRo1TvWdqonhb2gm2TPMp0O0X4ULAQ");
        var payload = message.GetPayload(serverKey.PublicCopy(), clientKey);
        Assert.AreEqual(text, Encoding.UTF8.GetString(payload));
        // Client generate a response (to be sent to the server) //
        var response = new Message(Guid.NewGuid());
        response.SetPayload(Encoding.UTF8.GetBytes(text), serverKey.PublicCopy(), clientKey);
        response.Sign(Key.Generate(new List<KeyCapability>() {KeyCapability.Sign}, null));
        var exported = response.Export();
        // This would really happen on the server side //
        var received = Item.Import<Message>(exported);
        var payload2 = message.GetPayload(serverKey, clientKey.PublicCopy());
        Assert.AreEqual(text, Encoding.UTF8.GetString(payload2));
    }
    /*
    [TestMethod]
    public void AlienMessageEncryptionTest2() {
        var clientKey = Item.Import<Key>("Di:KEY.eyJ1aWQiOiI1MTllNWE5Mi01Yjc1LTQxMTctODZjMS1jMTFjZjI0MDY1YmUiLCJpYXQiOiIyMDIyLTA3LTAxVDA5OjEwOjEwLjc3MTQ2OFoiLCJrZXkiOiIyREJWdDhWOWdaekE1VktpV2JHWmZGYnFLTVFnbkJtb2dQRHU5R0JueUMzWXVpVVROZFZCc2hoZnAiLCJwdWIiOiIyREJWdG5NYTFZM1B6a25FN3ZXTnJybkgyM0JVVlJROXVwRGM1Umd0MnloVFNEMUZoOFNiMXBhR3cifQ");
        var serverKey = Item.Import<Key>("Di:KEY.eyJpYXQiOiIyMDIyLTA3LTAxVDA4OjM2OjIwLjI2ODQ1M1oiLCJwdWIiOiIyREJWdG5NYWFYcWs1ZEFjWk5EY0hRNUpIc3ZpVkQzYk52N0p5Q1BvNmFHMWNna2RUWGJ0UEFLOUQiLCJ1aWQiOiI5ZTkzMzE0Yy02ZjAwLTQxYzAtYjQxMC1kMjhiNWIzYjllNWUiLCJ1c2UiOlsiZXhjaGFuZ2UiXX0");
        var message = Item.Import<Message>("Di:MSG.eyJpYXQiOiIyMDIyLTA3LTAxVDA5OjE0OjUyLjEyMDg3NFoiLCJpc3MiOiIyZmMyMTA4NC1iNWVkLTQ5MjAtODlmMy03MTZiNGZmMmJmM2IiLCJ1aWQiOiI4M2Y5ZmI5YS1mOTYzLTQwOGUtOWFmNi0zZGZjNzk1OWM1NmYifQ.RBMBBjkDEVjCIIZ14BTEZKzcRYtYkm+CpiS/jTVZNJAUUE2zdhMSTyti/7lSSL4E0y4q8b4d8MOkrfzyFb0Qe9moCotg.1t5uoavxedfJXrtgx5qJ9n7nJ30Tp0cb3kXoAJHD+TFcRHwMY8G3x+bgLgS8Bd1gnzlQgf4BAvIZelGQrzdlDw");
        var payload = message.GetPayload(clientKey, serverKey);
        Assert.AreEqual("Commons.Payload, Encoding.UTF8.GetString(payload));
        // TODO: add message.verity here
    }

    [TestMethod]
    public void AlienMessageEncodingTest1()
    {
        const string alienMessage = "Di:MSG.eyJleHAiOiIyMDIyLTA2LTA4VDA5OjUxOjA4LjA3Mzk2MTNaIiwiaXNzIjoiNTFEQzdEMDEtODdEQy00NEM1LTlEMjctMEVGMjZEMjdCODVGIiwidWlkIjoiMTU3MjdFQTMtNDk0QS00QzVGLUE1M0UtMDE4Q0IyMUEzMjM5IiwiY3R4IjoiY29ubmVjdGlvbi1yZXF1ZXN0IiwiaWF0IjoiMjAyMi0wNi0wOFQwOTo0OTowOC4wNzM5NjEzWiJ9.eyJyZXF1ZXN0Ijp7InR5cCI6NSwiYWRkIjpbeyJ0eXAiOjEsIm1zZyI6IldlIHdpbGwgc2VuZCBhbiBTTVMgdG8gMDcqKioqKioqKjE5In1dLCJyZWYiOiJhR2J1RXdGYlVkfDV8RkpzQ09zb251bEtpMHRiTSIsImhkciI6IkJCTCAtIEFkZCBDb25uZWN0aW9uIiwibXNnIjoiRG8geW91IHdhbnQgdG8gY29ubmVjdCB0aGlzIHBob25lIHRvIEJCTD8ifX0.iAWGwidsaiI49xj2oNy5F2Yxubi+PC8WduUF+UuRQItxu4w60ILCnyWxRMD4kO78I1fcmbkDKbOa/o5+AgbhCA";
        var message = Item.Import<Message>(alienMessage);
        var reExported = message.Export();
        Assert.AreEqual(alienMessage, reExported);
    }
*/
}