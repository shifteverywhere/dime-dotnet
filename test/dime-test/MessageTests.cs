//
//  MessageTests.cs
//  DiME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class MessageTests
    {
        [TestMethod]
        public void MessageTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            ProfileVersion profile = ProfileVersion.One;
            Guid subjectId = Guid.NewGuid();
            KeyBox keypair = KeyBox.Generate(KeyType.Identity, profile);
            Identity issuer = Commons.SenderIdentity;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Message message = new Message(subjectId, issuer, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsTrue(profile == message.Profile);
            Assert.IsNotNull(message.Id);
            Assert.AreEqual(subjectId, message.SubjectId);
            Assert.AreEqual(issuer.IdentityKey, message.Identity.IdentityKey);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
            Assert.IsTrue(message.IssuedAt >= now && message.IssuedAt <= (now + 1));
            Assert.IsTrue(message.ExpiresAt >= (now + 10) && message.ExpiresAt <= (now + 10));
        }

        [TestMethod]
        public void MessageTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Guid subjectId = Guid.NewGuid();
            Identity issuer = Commons.SenderIdentity;
            byte[] payload = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            long validFor = 10;
            Message message1 = new Message(subjectId, issuer, validFor);
            message1.SetPayload(payload);
            Message message2 = new Message(subjectId, issuer, validFor);
            message2.SetPayload(payload);
            Assert.AreNotEqual(message1.Id, message2.Id);
        }

        [TestMethod]
        public void MessageTest3()
        {
            try {
                Message message = new Message(Guid.NewGuid(), null, 10);
            } catch (ArgumentNullException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");         
        }

        [TestMethod]
        public void ExportTest1()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeypair.Key);
            string encoded = message.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith(Dime.DIME_HEADER));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 6);          
        }  

        [TestMethod]
        public void ExportTest2()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            try {
                message.Export();
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }  

        [TestMethod]
        public void ExportTest3()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeypair.Key);
            Assert.AreEqual(message.Export(), message.Export());
        }

        [TestMethod]
        public void VerifyTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            try{
                Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, -10);
                message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
                message.Seal(Commons.SenderKeypair.Key);
                message.Verify();
            } catch (DateExpirationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");     
        }

        [TestMethod]
        public void ImportTest1()
        {   
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "DI1.aW8uZGltZWZvcm1hdC5tc2c.REkxLmFXOHVaR2x0WldadmNtMWhkQzVwWkEuZXlKemRXSWlPaUkwTVRRMFpUa3dNaTB3WXpGa0xUUTRORGd0T1RCbVl5MWxaREJrT1RNek9HSTJNek1pTENKcGMzTWlPaUk1WVdVNE5EVm1aaTA0TnpRM0xUUXlZV0l0WW1SaFlpMWxZbU14TldNNE9HRTNOMlFpTENKcFlYUWlPakUyTWpNeE9ERXhNemNzSW1WNGNDSTZNVFkxTkRjeE56RXpOeXdpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFUbHpZVlZEUW5OY2RUQXdNa0pOTkhOU2FqVnVhVVoxUmxaWEwzTTFZazVGVUd4eVZsTTNTMGxNVm1aelVGSnFieUlzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpWFgwLlJFa3hMbUZYT0hWYVIyeDBXbGRhZG1OdE1XaGtRelZ3V2tFdVpYbEtlbVJYU1dsUGFVazFXVmRWTkU1RVZtMWFhVEEwVG5wUk0weFVVWGxaVjBsMFdXMVNhRmxwTVd4WmJVMTRUbGROTkU5SFJUTk9NbEZwVEVOS2NHTXpUV2xQYVVrelRsUkJNRTVxUVROTmFUQXhUV3BaTkV4VVVURmFWR2QwV1cxV2FFNVRNREphUkZGNFQxZEZOVTV0U1hsT2FrVnBURU5LY0ZsWVVXbFBha1V5VFdwTmVFOUVRVFJOVkdOelNXMVdOR05EU1RaTlZHTTBUVVJuTWsxRVozaE9lWGRwWVZkME5VbHFiMmxVVlU1MlpEQktVbGRWVWt4TmJGb3pVVmhzUmxGWGRIUmFiRlpYVW01bk1scFVRbHBpYTJ4d1QxWldZV0l4VVhsVlZrcEZUa2RhUkZGNlNUQldWMHBTV2toc01XSklUalJpV0dSalpGUkJkMDFyU2t0V1UwbHpTVzFPYUdORFNUWlhlVXB1V2xjMWJHTnRiR3BKYVhkcFlWaE9lbVJYVldsWVdEQXVkeXRMTUV3Mk1FSnVaM1ZDWW14Nk0zWmtjV2RKSzJkbk1HOURXWEYxZUhGVk5qQlFUVFZrUzFSVFIxTmpiMUJpYkRVM01sRnpTM0p0VlRGdmQwWnFWMHQzTjNSUVZUVndjR1ZSWlNzd2IyRnlVMHBLUkdjLk1KdS85c0tYK3VGNWtnRFNiSEh3ck50Rk9LSjk2dXBoNDdCRmRMWC9SVEthU3BBUU5WRlFjMTAzdkhwWTRLaVVQcURSd0w3eCtwUGRxTzlLcDl6ZEJR.eyJ1aWQiOiJjNGY3ZDJhNC0xNTQ5LTQ0ZGYtOGVhMS01MDVhMmQ5OThhYmYiLCJzdWIiOiIyNjBmZWM3Zi1jODgzLTQ4ZjMtODFmMS1lYTkyZTZiNTM1YmYiLCJpc3MiOiI0MTQ0ZTkwMi0wYzFkLTQ4NDgtOTBmYy1lZDBkOTMzOGI2MzMiLCJpYXQiOjE2MjMxODMxOTIsImV4cCI6MTYyMzE4MzIwMn0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.MgxHn8hjzvK5Mggn3FEc/6iS71CbAf5xLWWHpQhSAkcMrUpGhYAqMt7lO8QXqR4xEPHm7nBUaU+o2vA1NImWCQ";
            Message message = Dime.Import<Message>(encoded);
            Assert.AreEqual(ProfileVersion.One, message.Profile);
            Assert.AreEqual(new Guid("c4f7d2a4-1549-44df-8ea1-505a2d998abf"), message.Id);
            Assert.AreEqual(new Guid("260fec7f-c883-48f3-81f1-ea92e6b535bf"), message.SubjectId);
            Assert.AreEqual(new Guid("4144e902-0c1d-4848-90fc-ed0d9338b633"), message.IssuerId);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
            Assert.AreEqual(1623183192, message.IssuedAt);
            Assert.AreEqual(1623183202, message.ExpiresAt);
            Assert.IsNull(message.State);
            Assert.IsNotNull(message.Identity);
            Assert.AreEqual(message.IssuerId, message.Identity.SubjectId);
            Assert.AreEqual(new Guid("9ae845ff-8747-42ab-bdab-ebc15c88a77d"), message.Identity.IssuerId);
            Assert.AreEqual(1623181137, message.Identity.IssuedAt);
            Assert.AreEqual(1654717137, message.Identity.ExpiresAt);
            Assert.AreEqual("MCowBQYDK2VwAyEA9saUCBs\u002BM4sRj5niFuFVW/s5bNEPlrVS7KILVfsPRjo", message.Identity.IdentityKey);
        } 

        [TestMethod]
        public void ImportTest2()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiI1ZWRkMmFkZS1mZjRiLTQ1YzktODMyMy1iOTE4YWJmYWZkMjEiLCJzdWIiOiJiMzIyNTU3NC1jYTNkLTRlYWItODNlMC03NjU1MDE2ZWEyMmQiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjE5NzU2MzAsImV4cCI6MTYyMTk3NTY0MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
            try {
                Message message = Dime.Import<Message>(encoded);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ImportTest3()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "E1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.TTEuU1RFdVpYbEtlbVJYU1dsUGFVcG9XV3BXYVU5SFRYZGFRekZ0V2tSSk5FeFVVbXBOZWtGMFQwUlJlVnBwTUhwT1JHUnBUa1JvYWs5RVdtdFpiVTFwVEVOS2NHTXpUV2xQYVVrelRWZFZlVmx0VlRGWmVUQXpUVmRXYTB4VVVYbFphbEYwV1cxWk5VMXBNRFJhYlVwcFdtMVZNazFxUVROT01rMXBURU5LY0ZsWVVXbFBha1V5VFdwRk5VNTZTWGROYWxGelNXMVdOR05EU1RaTlZGa3hUWHBWZDA5RVFYbE9RM2RwWVZkME5VbHFiMmxVVlU1MlpEQktVbGRWVWt4TmJGb3pVVmhzUmxGWGJGUmtSMUl4VTI1d2QyUlZkSEZqTUhSTFRsWjRNVTFFUVhsUmJUVlFUMVZTTUZJd1RrOVRNWEJwWTBaQ1IxUlVWbEJPUmxKRlVucE5NVk13VmtsYWVVbHpTVzFPYUdORFNUWlhlVXBvWkZoU2IySXpTbkJsYlZWcFdGZ3dMbmREVjIweFQzRXhNSEZWSzNoUFlWWlZUVEp3UjFkSFVtUXhha2d4YzJGV1lYUkdNVWMyWnk5M1VGVXlTSFk1ZEdGU1dHaElOR3RXVldjME5uRmpjVTB5VFRSS2QwSlZabTh4YldNMmRVMTBaMUpPU2tKUi5leUoxYVdRaU9pSmpZamd5TVdVNE15MHdaV0l4TFRSbVlUQXRZVGc0TUMweU5HVXpaREl6WmpRMlltSWlMQ0p6ZFdJaU9pSm1OREl5T1RVek1pMWhNelV5TFRRM05qZ3RPV0k0WWkxaE5UWTBZemRqWWpKalpEWWlMQ0pwYzNNaU9pSmhZalZpT0dNd1pDMW1aREk0TFRSak16QXRPRFF5Wmkwek5EZGlORGhqT0Raa1ltTWlMQ0pwWVhRaU9qRTJNakl3TlRrek9URXNJbVY0Y0NJNk1UWXlNakExT1RRd01YMC5VbUZqWldOaGNpQnBjeUJ5WVdObFkyRnlJR0poWTJ0M1lYSmtjeTQuV3VKMTRkY0d3bmJwamFiYjkwOHA2SVdCTGdoS3d2REhWRzNoc1dQV3Q1ZFVVQjNub2JwLzBPUHJUM09VcitENHhEemtBcXpvRUVQM2cyeUNCU2djQ1E.eyJ1aWQiOiI1YTdmY2ZmZS01NGRhLTQwZDQtOGY2My1hMDA5MmIwNTdkOWMiLCJzdWIiOiJmNDIyOTUzMi1hMzUyLTQ3NjgtOWI4Yi1hNTY0YzdjYjJjZDYiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjIwNTkzOTEsImV4cCI6MTYyMjA1OTQwMX0.Zz+c1e3H2jrdqmhzoacUnrr3Wz1KaR//JRLQeEmQ4hmQrSszwg/vEvYZo+3KK4xl/cNh2A2YOyXwzD+o8Lm/Aw";
            try {
                Dime.Import<Message>(encoded);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest1()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            try {
                message.Seal(Commons.SenderKeypair.Key);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSealedTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsFalse(message.IsSealed);
            message.Seal(Commons.SenderKeypair.Key);
            Assert.IsTrue(message.IsSealed);
        }
        
        [TestMethod]
        public void IdTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeypair.Key);
            Guid uid1 = message.Id;
            message.ExpiresAt = message.ExpiresAt + 100;
            Assert.AreNotEqual(uid1, message.Id);
        }

        [TestMethod]
        public void GetPayloadTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Identity issuer = Commons.SenderIdentity;
            Message message1 = new Message(Guid.NewGuid(), issuer, 100);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message1.GetPayload()));
            message1.Seal(Commons.SenderKeypair.Key);
            string encoded = message1.Export();
            Message message2 = Dime.Import<Message>(encoded);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message2.GetPayload()));
        }

        [TestMethod]
        public void LinkMessageTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Identity issuer = Commons.SenderIdentity;
            Identity receiver = Commons.ReceiverIdentity;
            Message issuerMessage = new Message(receiver.SubjectId, issuer, 100);
            issuerMessage.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage.Seal(Commons.SenderKeypair.Key);
            string issuerEncoded = issuerMessage.Export();
            
            Message receivedMessage = Dime.Import<Message>(issuerEncoded);
            Message responseMessage = new Message(issuer.SubjectId, receiver, 100);
            responseMessage.SetPayload(Encoding.UTF8.GetBytes("It is!"));
            responseMessage.LinkMessage(receivedMessage);
            responseMessage.Seal(Commons.ReceiverKeypair.Key);
            string responseEncoded = responseMessage.Export();

            Message finalMessage = Dime.Import<Message>(responseEncoded);
            finalMessage.Verify(issuerMessage);
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message1 = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity, 100);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message1.Seal(Commons.SenderKeypair.Key);
            string thumbprint1 = message1.Thumbprint();
            string encoded = message1.Export();
            Message message2 = Dime.Import<Message>(encoded);
            string thumbprint2 = message2.Thumbprint();
            Assert.AreEqual(thumbprint1, thumbprint2);
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Identity issuer = Commons.SenderIdentity;
            Identity receiver = Commons.ReceiverIdentity;
            Message issuerMessage1 = new Message(receiver.SubjectId, issuer, 100);
            issuerMessage1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage1.Seal(Commons.SenderKeypair.Key);
            Message issuerMessage2 = new Message(receiver.SubjectId, issuer, 100);
            issuerMessage2.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage2.Seal(Commons.SenderKeypair.Key);
            Assert.AreNotEqual(issuerMessage1.Thumbprint(), issuerMessage2.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest3()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity, 100);
            try {
                message.Thumbprint();
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }
 
    }

}
