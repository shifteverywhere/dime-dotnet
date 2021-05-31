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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            ProfileVersion profile = ProfileVersion.One;
            Guid subjectId = Guid.NewGuid();
            KeyBox keypair = KeyBox.GenerateKey(KeyType.Identity, profile);
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeypair.Key);
            string encoded = message.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("M" + (int)message.Profile));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 5);          
        }  

        [TestMethod]
        public void ExportTest2()
        {  
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            try {
                message.Export();
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }  

        [TestMethod]
        public void ExportTest3()
        {  
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeypair.Key);
            Assert.AreEqual(message.Export(), message.Export());
        }

        [TestMethod]
        public void VerifyTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            string encoded = "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiIyMzdlNWVlMi1hMDIwLTQ0YmYtOTZlZC02ZWVmNmZjZTE5NWMiLCJzdWIiOiIzODAxOTVkOC01ZjUyLTQzZmItOGVjNi0zN2RiYWRhZWNiNDkiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjIwNjEwMjgsImV4cCI6MTY1MzU5NzAyOH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.w66UHVASUtiIZAEbNTMel9VSFpiJ+IkuBiB2xZFQRZxi+7Xp4D+Ti9v5WF93Dqf0Jd20Wa9mFPsdhitWoPa/Bg";
            Message message = Dime.Import<Message>(encoded);
            Assert.AreEqual(ProfileVersion.One, message.Profile);
            Assert.AreEqual(new Guid("237e5ee2-a020-44bf-96ed-6eef6fce195c"), message.Id);
            Assert.AreEqual(new Guid("380195d8-5f52-43fb-8ec6-37dbadaecb49"), message.SubjectId);
            Assert.AreEqual(new Guid("ab5b8c0d-fd28-4c30-842f-347b48c86dbc"), message.IssuerId);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
            Assert.AreEqual(1622061028, message.IssuedAt);
            Assert.AreEqual(1653597028, message.ExpiresAt);
            Assert.IsNull(message.State);
            Assert.IsNotNull(message.Identity);
            Assert.AreEqual(message.IssuerId, message.Identity.SubjectId);
            Assert.AreEqual(new Guid("71e2be5c-71ed-42b4-bf92-8fbbfe62077c"), message.Identity.IssuerId);
            Assert.AreEqual(1621972024, message.Identity.IssuedAt);
            Assert.AreEqual(1653508024, message.Identity.ExpiresAt);
            Assert.AreEqual("MCowBQYDK2VwAyEAiStduJzpuKjsKJ5\u002BnO9DtGCNKZbpPFM5O4TDG35KEHg", message.Identity.IdentityKey);
        } 

        [TestMethod]
        public void ImportTest2()
        {  
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            string encoded = "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiI1ZWRkMmFkZS1mZjRiLTQ1YzktODMyMy1iOTE4YWJmYWZkMjEiLCJzdWIiOiJiMzIyNTU3NC1jYTNkLTRlYWItODNlMC03NjU1MDE2ZWEyMmQiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjE5NzU2MzAsImV4cCI6MTYyMTk3NTY0MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
            try {
                Message message = Dime.Import<Message>(encoded);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ImportTest3()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            string encoded = "E1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.TTEuU1RFdVpYbEtlbVJYU1dsUGFVcG9XV3BXYVU5SFRYZGFRekZ0V2tSSk5FeFVVbXBOZWtGMFQwUlJlVnBwTUhwT1JHUnBUa1JvYWs5RVdtdFpiVTFwVEVOS2NHTXpUV2xQYVVrelRWZFZlVmx0VlRGWmVUQXpUVmRXYTB4VVVYbFphbEYwV1cxWk5VMXBNRFJhYlVwcFdtMVZNazFxUVROT01rMXBURU5LY0ZsWVVXbFBha1V5VFdwRk5VNTZTWGROYWxGelNXMVdOR05EU1RaTlZGa3hUWHBWZDA5RVFYbE9RM2RwWVZkME5VbHFiMmxVVlU1MlpEQktVbGRWVWt4TmJGb3pVVmhzUmxGWGJGUmtSMUl4VTI1d2QyUlZkSEZqTUhSTFRsWjRNVTFFUVhsUmJUVlFUMVZTTUZJd1RrOVRNWEJwWTBaQ1IxUlVWbEJPUmxKRlVucE5NVk13VmtsYWVVbHpTVzFPYUdORFNUWlhlVXBvWkZoU2IySXpTbkJsYlZWcFdGZ3dMbmREVjIweFQzRXhNSEZWSzNoUFlWWlZUVEp3UjFkSFVtUXhha2d4YzJGV1lYUkdNVWMyWnk5M1VGVXlTSFk1ZEdGU1dHaElOR3RXVldjME5uRmpjVTB5VFRSS2QwSlZabTh4YldNMmRVMTBaMUpPU2tKUi5leUoxYVdRaU9pSmpZamd5TVdVNE15MHdaV0l4TFRSbVlUQXRZVGc0TUMweU5HVXpaREl6WmpRMlltSWlMQ0p6ZFdJaU9pSm1OREl5T1RVek1pMWhNelV5TFRRM05qZ3RPV0k0WWkxaE5UWTBZemRqWWpKalpEWWlMQ0pwYzNNaU9pSmhZalZpT0dNd1pDMW1aREk0TFRSak16QXRPRFF5Wmkwek5EZGlORGhqT0Raa1ltTWlMQ0pwWVhRaU9qRTJNakl3TlRrek9URXNJbVY0Y0NJNk1UWXlNakExT1RRd01YMC5VbUZqWldOaGNpQnBjeUJ5WVdObFkyRnlJR0poWTJ0M1lYSmtjeTQuV3VKMTRkY0d3bmJwamFiYjkwOHA2SVdCTGdoS3d2REhWRzNoc1dQV3Q1ZFVVQjNub2JwLzBPUHJUM09VcitENHhEemtBcXpvRUVQM2cyeUNCU2djQ1E.eyJ1aWQiOiI1YTdmY2ZmZS01NGRhLTQwZDQtOGY2My1hMDA5MmIwNTdkOWMiLCJzdWIiOiJmNDIyOTUzMi1hMzUyLTQ3NjgtOWI4Yi1hNTY0YzdjYjJjZDYiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjIwNTkzOTEsImV4cCI6MTYyMjA1OTQwMX0.Zz+c1e3H2jrdqmhzoacUnrr3Wz1KaR//JRLQeEmQ4hmQrSszwg/vEvYZo+3KK4xl/cNh2A2YOyXwzD+o8Lm/Aw";
            try {
                Dime.Import<Message>(encoded);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest1()
        {  
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            try {
                message.Seal(Commons.SenderKeypair.Key);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSealedTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsFalse(message.IsSealed);
            message.Seal(Commons.SenderKeypair.Key);
            Assert.IsTrue(message.IsSealed);
        }
        
        [TestMethod]
        public void IdTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
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
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            try {
                message.Thumbprint();
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }
 
    }

}
