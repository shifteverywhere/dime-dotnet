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
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
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
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
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
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeybox);
            string encoded = message.ToString();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith(Message.IID));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 4);          
        }  

        [TestMethod]
        public void ToStringTest2()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            try {
                message.ToString();
            } catch (FormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }  

        [TestMethod]
        public void ToStringTest3()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeybox);
            Assert.AreEqual(message.ToString(), message.ToString());
        }

        [TestMethod]
        public void VerifyTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
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
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, untrustedSender.SubjectId, 120);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(keypair);
            try {
                message.Verify(Commons.SenderKeybox);
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void FromStringTest1()
        {   
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "bXNn.eyJ1aWQiOiI3MGMzOTQ5OC1mMWIwLTQ4ODgtOWY0Ny0yNzVmZTFhOWIwMTQiLCJhdWQiOiJhZjM4NGQwMC05YmM1LTQwMTctODc3YS01Mzc5ZjY1M2U1ZTUiLCJpc3MiOiI3MDUwMjgzMy01MjE1LTRiZTMtYjc1ZS0zZTNmMDdkMjU2MjQiLCJpYXQiOjE2MjYyMDg1MjUsImV4cCI6MTYyNjIwODUzNX0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.VTfqm8NPjBilgYd07pv7nb1ehCh81vRrKS8QIhK4ZcRrkilJ7WLrRAZljUpW1ALGPr5qgLx1Nalpvs3FVBfeCw";
            Message message = Message.FromString(encoded);
            Assert.AreEqual(new Guid("70c39498-f1b0-4888-9f47-275fe1a9b014"), message.UID);
            Assert.AreEqual(new Guid("af384d00-9bc5-4017-877a-5379f653e5e5"), message.AudienceId);
            Assert.AreEqual(new Guid("70502833-5215-4be3-b75e-3e3f07d25624"), message.IssuerId);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message.GetPayload()));
            Assert.AreEqual(1626208525, message.IssuedAt);
            Assert.AreEqual(1626208535, message.ExpiresAt);
            Assert.AreEqual(message.IssuerId, Commons.SenderIdentity.SubjectId);
        } 

        [TestMethod]
        public void FromStringTest2()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            string encoded = "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiI1ZWRkMmFkZS1mZjRiLTQ1YzktODMyMy1iOTE4YWJmYWZkMjEiLCJzdWIiOiJiMzIyNTU3NC1jYTNkLTRlYWItODNlMC03NjU1MDE2ZWEyMmQiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjE5NzU2MzAsImV4cCI6MTYyMTk3NTY0MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4";
            try {
                Message message = Message.FromString(encoded);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void FromStringTest3()
        {  
            Message message1 = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 120);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message1.Seal(Commons.SenderKeybox);
            string encoded = message1.ToString();
            Message message2 = Message.FromString(encoded);
            message2.Verify(Commons.SenderKeybox);
        }

        [TestMethod]
        public void SealTest1()
        {  
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            try {
                message.Seal(Commons.SenderKeybox);
            } catch (FormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSealedTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 10);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsFalse(message.IsSealed);
            message.Seal(Commons.SenderKeybox);
            Assert.IsTrue(message.IsSealed);
        }
        
        [TestMethod]
        public void GetPayloadTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Identity issuer = Commons.SenderIdentity;
            Message message1 = new Message(Commons.ReceiverIdentity.SubjectId, issuer.SubjectId, 100);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message1.GetPayload()));
            message1.Seal(Commons.SenderKeybox);
            string encoded = message1.ToString();
            Message message2 = Message.FromString(encoded);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message2.GetPayload()));
        }

        [TestMethod]
        public void LinkItemTest1()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Identity issuer = Commons.SenderIdentity;
            Identity receiver = Commons.ReceiverIdentity;
            Message issuerMessage = new Message(receiver.SubjectId, issuer.SubjectId, 100);
            issuerMessage.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage.Seal(Commons.SenderKeybox);
            string issuerEncoded = issuerMessage.ToString();
            Message receivedMessage = Message.FromString(issuerEncoded);
            Message responseMessage = new Message(issuer.SubjectId, receiver.SubjectId, 100);
            responseMessage.SetPayload(Encoding.UTF8.GetBytes("It is!"));
            responseMessage.LinkItem(issuerMessage);
            responseMessage.Seal(Commons.ReceiverKeybox);
            string responseEncoded = responseMessage.ToString();
            Message finalMessage = Message.FromString(responseEncoded);
            finalMessage.Verify(Commons.ReceiverKeybox, issuerMessage);
        }

        [TestMethod]
        public void LinkItemTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
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
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
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
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
            Message message1 = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message1.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message1.Seal(Commons.SenderKeybox);
            string thumbprint1 = message1.Thumbprint();
            string encoded = message1.ToString();
            Message message2 = Message.FromString(encoded);
            string thumbprint2 = message2.Thumbprint();
            Assert.AreEqual(thumbprint1, thumbprint2);
        }

        [TestMethod]
        public void ThumbprintTest2()
        {
            Dime.SetTrustedIdentity(Commons.TrustedIdentity);
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
