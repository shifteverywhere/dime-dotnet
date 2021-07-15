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
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsNotNull(message.UID);
            Assert.AreEqual(Commons.ReceiverIdentity.SubjectId, message.AudienceId);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
            Assert.IsTrue(message.IssuedAt >= now && message.IssuedAt <= (now + 1));
            Assert.IsTrue(message.ExpiresAt >= (now + 10) && message.ExpiresAt <= (now + 10));
        }

        [TestMethod]
        public void MessageTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            byte[] payload = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            long validFor = 10;
            Message message1 = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, validFor);
            message1.SetPayload(payload);
            Message message2 = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, validFor);
            message2.SetPayload(payload);
            Assert.AreNotEqual(message1.UID, message2.UID);
        }

        [TestMethod]
        public void ToStringTest1()
        {  
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeybox);
            string encoded = message.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith($"{Envelope.HEADER}:{Message.TAG}"));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 4);          
        }  

        [TestMethod]
        public void ToStringTest2()
        {  
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            try {
                message.Export();
            } catch (FormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }  

        [TestMethod]
        public void ToStringTest3()
        {  
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeybox);
            Assert.AreEqual(message.Export(), message.Export());
        }

        [TestMethod]
        public void VerifyTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, -10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeybox);
            try {
                message.Verify(Commons.SenderKeybox);
            } catch (DateExpirationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");     
        }

        [TestMethod]
        public void VerifyTest2()
        {
            List<Capability> caps = new List<Capability> { Capability.Identify };
            KeyBox keypair = KeyBox.Generate(KeyType.Identity);
            Identity untrustedSender = IdentityIssuingRequest.Generate(keypair).IssueIdentity(Guid.NewGuid(), 120, caps,  keypair,  null);
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, untrustedSender.SubjectId, 120);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(keypair);
            try {
                message.Verify(Commons.SenderKeybox);
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ExportTest1()
        {   
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "Di:MSG.eyJ1aWQiOiI0NzEzOTc0Ni0wODdhLTQ0ZmYtYTEwNi0yMzZhM2NmNzdmYTciLCJhdWQiOiIwZTMyZGY2Zi0xNjg3LTQwNTktODIyOS0yM2E2NzlhODExYzkiLCJpc3MiOiIzNGU3MDgxYi04ODcxLTQ2N2EtYTk2My03ZjBlZWRiNDJjODAiLCJpYXQiOjE2MjYzNzg4NDEsImV4cCI6MTYyNjM3ODg1MX0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.ASkLvPlPcgrzFusLAulkOUCL1ZnMw5L8g4uZlbpwj5ClmQKOFpGdOOcxb9wLlHi8lZoFobqoxlvDR4Q11YkGiAc";
            Message message = Item.Import<Message>(encoded);
            Assert.AreEqual(new Guid("47139746-087a-44ff-a106-236a3cf77fa7"), message.UID);
            Assert.AreEqual(new Guid("0e32df6f-1687-4059-8229-23a679a811c9"), message.AudienceId);
            Assert.AreEqual(new Guid("34e7081b-8871-467a-a963-7f0eedb42c80"), message.IssuerId);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
            Assert.AreEqual(1626378841, message.IssuedAt);
            Assert.AreEqual(1626378851, message.ExpiresAt);
            Assert.AreEqual(message.IssuerId, Commons.SenderIdentity.SubjectId);
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
            Message message1 = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 120);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message1.Seal(Commons.SenderKeybox);
            string encoded = message1.Export();
            Message message2 = Item.Import<Message>(encoded);
            message2.Verify(Commons.SenderKeybox);
        }

        [TestMethod]
        public void SealTest1()
        {  
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            try {
                message.Seal(Commons.SenderKeybox);
            } catch (FormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSealedTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsFalse(message.IsSealed);
            message.Seal(Commons.SenderKeybox);
            Assert.IsTrue(message.IsSealed);
        }
        
        [TestMethod]
        public void GetPayloadTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Identity issuer = Commons.SenderIdentity;
            Message message1 = new Message(Commons.ReceiverIdentity.SubjectId, issuer.SubjectId, 100);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message1.GetPayload()));
            message1.Seal(Commons.SenderKeybox);
            string encoded = message1.Export();
            Message message2 = Item.Import<Message>(encoded);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message2.GetPayload()));
        }

        [TestMethod]
        public void LinkItemTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Identity issuer = Commons.SenderIdentity;
            Identity receiver = Commons.ReceiverIdentity;
            Message issuerMessage = new Message(receiver.SubjectId, issuer.SubjectId, 100);
            issuerMessage.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage.Seal(Commons.SenderKeybox);
            string issuerEncoded = issuerMessage.Export();
            Message receivedMessage = Item.Import<Message>(issuerEncoded);
            Message responseMessage = new Message(issuer.SubjectId, receiver.SubjectId, 100);
            responseMessage.SetPayload(Encoding.UTF8.GetBytes("It is!"));
            responseMessage.LinkItem(issuerMessage);
            responseMessage.Seal(Commons.ReceiverKeybox);
            string responseEncoded = responseMessage.Export();
            Message finalMessage = Item.Import<Message>(responseEncoded);
            finalMessage.Verify(Commons.ReceiverKeybox, issuerMessage);
        }

        [TestMethod]
        public void LinkItemTest2()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.LinkItem(KeyBox.Generate(KeyType.Exchange));
            message.Seal(Commons.SenderKeybox);
            try {
                message.Verify(Commons.SenderKeybox, Commons.SenderKeybox);
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }
        
        [TestMethod]
        public void LinkItemTest3()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeybox);
            try {
                message.LinkItem(KeyBox.Generate(KeyType.Exchange));
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            Identity.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message1 = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message1.Seal(Commons.SenderKeybox);
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
            Identity issuer = Commons.SenderIdentity;
            Identity receiver = Commons.ReceiverIdentity;
            Message issuerMessage1 = new Message(receiver.SubjectId, issuer.SubjectId, 100);
            issuerMessage1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage1.Seal(Commons.SenderKeybox);
            Message issuerMessage2 = new Message(receiver.SubjectId, issuer.SubjectId, 100);
            issuerMessage2.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage2.Seal(Commons.SenderKeybox);
            Assert.AreNotEqual(issuerMessage1.Thumbprint(), issuerMessage2.Thumbprint());
        }
 
    }

}
