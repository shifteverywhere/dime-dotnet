//
//  MessageTests.cs
//  Di:ME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Collections.Generic;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class MessageTests
    {
        [TestMethod]
        public void MessageTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            DateTime now = DateTime.Now;
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsNotNull(message.UniqueId);
            Assert.AreEqual(Commons.AudienceIdentity.SubjectId, message.AudienceId);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
            Assert.IsTrue(message.IssuedAt >= now && message.IssuedAt <= (now.AddSeconds(1)));
            Assert.IsTrue(message.ExpiresAt > (now.AddSeconds(9)) && message.ExpiresAt < (now.AddSeconds(11)));
        }

        [TestMethod]
        public void MessageTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            byte[] payload = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            long validFor = 10;
            Message message1 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, validFor);
            message1.SetPayload(payload);
            Message message2 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, validFor);
            message2.SetPayload(payload);
            Assert.AreNotEqual(message1.UniqueId, message2.UniqueId);
        }

        [TestMethod]
        public void ExportTest1()
        {  
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            string encoded = message.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith($"{Envelope.HEADER}:{Message.TAG}"));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 4);          
        }  

        [TestMethod]
        public void ExportTest2()
        {  
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10);
            try {
                message.Export();
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }  

        [TestMethod]
        public void ExportTest3()
        {  
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            Assert.AreEqual(message.Export(), message.Export());
        }

        [TestMethod]
        public void VerifyTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, -10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            try {
                message.Verify(Commons.IssuerKey);
            } catch (DateExpirationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");     
        }

        [TestMethod]
        public void VerifyTest2()
        {
            List<Capability> caps = new List<Capability> { Capability.Identify };
            Key keypair = Key.Generate(KeyType.Identity);
            Identity untrustedSender = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 120, caps,  keypair,  null);
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, untrustedSender.SubjectId, 120);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(keypair);
            try {
                message.Verify(Commons.IssuerKey);
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void VerifyTest3()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 120);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            message.Verify(Commons.IssuerIdentity.PublicKey);
        }

        [TestMethod]
        public void ImportTest1()
        {   
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "Di:MSG.eyJ1aWQiOiIzMjgwYzFlNy1mOGExLTRkM2ItYjNkZS03ZDAzNTIwZTBmYTMiLCJhdWQiOiI0ZDAzMTM1Zi0wZTBkLTQ4YjYtYTQ0Ny01ZDM1YmU3ODE5ZjkiLCJpc3MiOiI2MDY2OTQ1My1jNGQ5LTQ2MjgtODg4MC05NmM0YmUyNWQzY2UiLCJpYXQiOiIyMDIxLTA4LTA5VDE4OjQ2OjMyLjA2NDc3OFoiLCJleHAiOiIyMDIxLTA4LTA5VDE4OjQ2OjQyLjA2NDc3OFoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.AWKKiB8Rbq6myeuyZDRkZgJ6xko57OIsL2+c9c1wTgcIrOaZBUSUhTQ6ieepwtZjd6rNGLiBHvB1uKUn9TJkTgs";
            Message message = Item.Import<Message>(encoded);
            Assert.AreEqual(new Guid("3280c1e7-f8a1-4d3b-b3de-7d03520e0fa3"), message.UniqueId);
            Assert.AreEqual(new Guid("4d03135f-0e0d-48b6-a447-5d35be7819f9"), message.AudienceId);
            Assert.AreEqual(new Guid("60669453-c4d9-4628-8880-96c4be25d3ce"), message.IssuerId);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
            Assert.AreEqual(DateTime.Parse("2021-08-09T18:46:32.064778Z"), message.IssuedAt);
            Assert.AreEqual(DateTime.Parse("2021-08-09T18:46:42.064778Z"), message.ExpiresAt);
            Assert.AreEqual(message.IssuerId, Commons.IssuerIdentity.SubjectId);
        } 

        [TestMethod]
        public void ImportTest2()
        {  
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiI1ZWRkMmFkZS1mZjRiLTQ1YzktODMyMy1iOTE4YWJmYWZkMjEiLCJzdWIiOiJiMzIyNTU3NC1jYTNkLTRlYWItODNlMC03NjU1MDE2ZWEyMmQiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjE5NzU2MzAsImV4cCI6MTYyMTk3NTY0MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
            try {
                Message message = Item.Import<Message>(encoded);
            } catch (FormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ImportTest3()
        {  
            Message message1 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 120);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message1.Sign(Commons.IssuerKey);
            string encoded = message1.Export();
            Message message2 = Item.Import<Message>(encoded);
            message2.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void SealTest1()
        {  
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10);
            try {
                message.Sign(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSealedTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsFalse(message.IsSigned);
            message.Sign(Commons.IssuerKey);
            Assert.IsTrue(message.IsSigned);
        }
        
        [TestMethod]
        public void SetPayloadTest1()
        {
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
        }

        [TestMethod]
        public void SetPayloadTest2()
        {
            Message message1 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message1.GetPayload()));
            message1.Sign(Commons.IssuerKey);
            Message message2 = Item.Import<Message>(message1.Export());
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message2.GetPayload()));
        }

        [TestMethod]
        public void SetPayloadTest3()
        {
            Key localAudienceKeyBox = Key.Generate(KeyType.Exchange);
            Key remoteAudenceKeyBox = localAudienceKeyBox.PublicCopy();
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."), remoteAudenceKeyBox);
            try {
                byte[] payload = message.GetPayload();
            } catch (ArgumentNullException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SetPayloadTest4()
        {
            Key localAudienceKeyBox = Key.Generate(KeyType.Exchange);
            Key remoteAudenceKeyBox = localAudienceKeyBox.PublicCopy();
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."), remoteAudenceKeyBox);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload(localAudienceKeyBox)));
        }

        [TestMethod]
        public void SetPayloadTest5()
        {
            Key localAudienceKeyBox = Key.Generate(KeyType.Exchange);
            Key remoteAudenceKeyBox = localAudienceKeyBox.PublicCopy();
            Message message1 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."), remoteAudenceKeyBox);
            message1.Sign(Commons.IssuerKey);
            Message message2 = Item.Import<Message>(message1.Export());
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message2.GetPayload(localAudienceKeyBox)));
        }

        [TestMethod]
        public void SetPayloadTest6()
        {
            Key keybox = Key.Generate(KeyType.Identity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            try {
                message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."), keybox);
            } catch (ArgumentException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void LinkItemTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Identity issuer = Commons.IssuerIdentity;
            Identity receiver = Commons.AudienceIdentity;
            Message issuerMessage = new Message(receiver.SubjectId, issuer.SubjectId, 100);
            issuerMessage.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage.Sign(Commons.IssuerKey);
            string issuerEncoded = issuerMessage.Export();
            Message receivedMessage = Item.Import<Message>(issuerEncoded);
            Message responseMessage = new Message(issuer.SubjectId, receiver.SubjectId, 100);
            responseMessage.SetPayload(Encoding.UTF8.GetBytes("It is!"));
            responseMessage.LinkItem(issuerMessage);
            responseMessage.Sign(Commons.AudienceKey);
            string responseEncoded = responseMessage.Export();
            Message finalMessage = Item.Import<Message>(responseEncoded);
            finalMessage.Verify(Commons.AudienceKey, issuerMessage);
        }

        [TestMethod]
        public void LinkItemTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.LinkItem(Key.Generate(KeyType.Exchange));
            message.Sign(Commons.IssuerKey);
            try {
                message.Verify(Commons.IssuerKey, Commons.IssuerKey);
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }
        
        [TestMethod]
        public void LinkItemTest3()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            try {
                message.LinkItem(Key.Generate(KeyType.Exchange));
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message1 = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message1.Sign(Commons.IssuerKey);
            string thumbprint1 = message1.Thumbprint();
            string encoded = message1.Export();
            Message message2 = Item.Import<Message>(encoded);
            string thumbprint2 = message2.Thumbprint();
            Assert.AreEqual(thumbprint1, thumbprint2);
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Identity issuer = Commons.IssuerIdentity;
            Identity receiver = Commons.AudienceIdentity;
            Message issuerMessage1 = new Message(receiver.SubjectId, issuer.SubjectId, 100);
            issuerMessage1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage1.Sign(Commons.IssuerKey);
            Message issuerMessage2 = new Message(receiver.SubjectId, issuer.SubjectId, 100);
            issuerMessage2.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage2.Sign(Commons.IssuerKey);
            Assert.AreNotEqual(issuerMessage1.Thumbprint(), issuerMessage2.Thumbprint());
        }
 
    }

}
