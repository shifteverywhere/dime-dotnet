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
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Message message = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsTrue(Commons.SenderIdentity.Profile == message.Profile);
            Assert.IsNotNull(message.Id);
            Assert.AreEqual(Commons.ReceiverIdentity.SubjectId, message.AudienceId);
            Assert.AreEqual(Commons.SenderIdentity.IdentityKey, message.Issuer.IdentityKey);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
            Assert.IsTrue(message.IssuedAt >= now && message.IssuedAt <= (now + 1));
            Assert.IsTrue(message.ExpiresAt >= (now + 10) && message.ExpiresAt <= (now + 10));
        }

        [TestMethod]
        public void MessageTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            byte[] payload = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            long validFor = 10;
            Message message1 = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, validFor);
            message1.SetPayload(payload);
            Message message2 = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, validFor);
            message2.SetPayload(payload);
            Assert.AreNotEqual(message1.Id, message2.Id);
        }

        [TestMethod]
        public void MessageTest3()
        {
            try {
                Message message = new Message(Commons.ReceiverIdentity, null, 10);
            } catch (ArgumentNullException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");         
        }

        [TestMethod]
        public void ExportTest1()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeypair.Key);
            string encoded = message.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith(Dime.HEADER));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 7);          
        }  

        [TestMethod]
        public void ExportTest2()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, 10);
            try {
                message.Export();
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }  

        [TestMethod]
        public void ExportTest3()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeypair.Key);
            Assert.AreEqual(message.Export(), message.Export());
        }

        [TestMethod]
        public void VerifyTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            try{
                Message message = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, -10);
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
            string encoded = "DiME:aW8uZGltZWZvcm1hdC5pZA.eyJ2ZXIiOjEsInVpZCI6Ijg0NjE0YjU0LWE2NGUtNGU2Zi04ODhmLTUwMzliOWZhNjRmYyIsInN1YiI6ImFkZDIwZmY0LTMyMmItNGQ1NC1iYzc0LWJjYjVjN2VhMDhkNiIsImlzcyI6ImNmOWRlMjMxLTdkYmQtNDA0OS04MDFhLTBiZDUzMjE0ZTMzNSIsImlhdCI6MTYyMzI3NjI4OSwiZXhwIjoxNjU0ODEyMjg5LCJpa3kiOiJNQ293QlFZREsyVndBeUVBcDgyMFx1MDAyQnhlUWhZZFFlM3pMSjRObFNNR3hKOFhLOS9OOHVaZDJnOHZBSlZnIiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.YVc4dVpHbHRaV1p2Y20xaGRDNXBaQS5leUoyWlhJaU9qRXNJblZwWkNJNklqQTVNelExTVdSaUxUSTJaakl0TkRCak5TMDRabVE1TFRZM00yVTFaalV3WVRZNU5DSXNJbk4xWWlJNkltTm1PV1JsTWpNeExUZGtZbVF0TkRBME9TMDRNREZoTFRCaVpEVXpNakUwWlRNek5TSXNJbWx6Y3lJNklqRTNaVFppTnpnM0xXUTJaV1l0TkRFMU9DMWhZak01TFRoaU5XWmpNamczTlRjelpTSXNJbWxoZENJNk1UWXlNekkzTkRRNE55d2laWGh3SWpveE56Z3dPVFUwTkRnM0xDSnBhM2tpT2lKTlEyOTNRbEZaUkVzeVZuZEJlVVZCUlZsd2JXbGxiRTUzYmtSNlpHTkphbWxMYlVaUFZURjFabWRuVEhGWk9XZFZORk4zYUU1NWN6TXhTU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVhOemRXVWlYWDAuc0pJZXZZYjcybWppRTdXOHZPS3Ywbmk5MGUzSVhhd1lsOGZuWVhsMzRJbzRlUU1tZ05DYkdUN1N2MXFIclBhcjIxZ1FkZGVVQUdZaFVzM1hwbFIyQWc.revzfv1JwJG3/m/IKY3bVm5VFxMB/epmfe/0gqxhXD0rbUdvj+j22QLhuyhKqRe1XScOypk+TiwZ2RW0BKEUAA:aW8uZGltZWZvcm1hdC5tc2c.eyJ1aWQiOiJlY2U2Mjk2YS00MGRhLTRhMzQtOWUyOS1mYjVkMGJmNjBiNjgiLCJhdWQiOiIyZjRjYmY2Ni05ZWRiLTRkZTEtYjdhOC0yNDRmNmUwYzdmMmYiLCJpc3MiOiJhZGQyMGZmNC0zMjJiLTRkNTQtYmM3NC1iY2I1YzdlYTA4ZDYiLCJpYXQiOjE2MjMzNTc3NzQsImV4cCI6MTYyMzM1Nzc4NH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.7giyOR57qvUmMhcCGaUt8guEQYgekcOFdoQ4Fdw7TwPkIWnTyx9ab6xAai2tpFWKC2/V3PCKoycFKDuh9dU1AQ";
            Message message = Dime.Import<Message>(encoded);
            Assert.AreEqual(ProfileVersion.One, message.Profile);
            Assert.AreEqual(new Guid("ece6296a-40da-4a34-9e29-fb5d0bf60b68"), message.Id);
            Assert.AreEqual(new Guid("2f4cbf66-9edb-4de1-b7a8-244f6e0c7f2f"), message.AudienceId);
            Assert.AreEqual(new Guid("add20ff4-322b-4d54-bc74-bcb5c7ea08d6"), message.IssuerId);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
            Assert.AreEqual(1623357774, message.IssuedAt);
            Assert.AreEqual(1623357784, message.ExpiresAt);
            Assert.IsNotNull(message.Issuer);
            Assert.AreEqual(message.IssuerId, message.Issuer.SubjectId);
            Assert.AreEqual(new Guid("add20ff4-322b-4d54-bc74-bcb5c7ea08d6"), message.Issuer.SubjectId);
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
            Message message = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, 10);
            try {
                message.Seal(Commons.SenderKeypair.Key);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSealedTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsFalse(message.IsSealed);
            message.Seal(Commons.SenderKeypair.Key);
            Assert.IsTrue(message.IsSealed);
        }
        
        [TestMethod]
        public void GetPayloadTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Identity issuer = Commons.SenderIdentity;
            Message message1 = new Message(Commons.ReceiverIdentity, issuer, 100);
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
            Message issuerMessage = new Message(receiver, issuer, 100);
            issuerMessage.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage.Seal(Commons.SenderKeypair.Key);
            string issuerEncoded = issuerMessage.Export();
            
            Message receivedMessage = Dime.Import<Message>(issuerEncoded);
            Message responseMessage = new Message(issuer, receiver, 100);
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
            Message message1 = new Message(Commons.ReceiverIdentity, Commons.SenderIdentity, 100);
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
            Message issuerMessage1 = new Message(receiver, issuer, 100);
            issuerMessage1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage1.Seal(Commons.SenderKeypair.Key);
            Message issuerMessage2 = new Message(receiver, issuer, 100);
            issuerMessage2.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage2.Seal(Commons.SenderKeypair.Key);
            Assert.AreNotEqual(issuerMessage1.Thumbprint(), issuerMessage2.Thumbprint());
        }
 
    }

}
