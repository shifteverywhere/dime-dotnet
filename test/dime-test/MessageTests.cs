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
            int profile = 1;
            Guid subjectId = Guid.NewGuid();
            Keypair keypair = Keypair.Generate(KeypairType.Identity, profile);
            Identity issuer = Commons.SenderIdentity;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Message message = new Message(subjectId, issuer, 10);
            message.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsTrue(1 == message.Profile);
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
            message1.AddPayload(payload);
            Message message2 = new Message(subjectId, issuer, validFor);
            message2.AddPayload(payload);
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
            message.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeypair.PrivateKey);
            string encoded = message.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("M" + message.Profile.ToString()));
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
            message.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Seal(Commons.SenderKeypair.PrivateKey);
            Assert.AreEqual(message.Export(), message.Export());
        }

        [TestMethod]
        public void ExportTest4()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            try{
                Message message = new Message(Guid.NewGuid(), Commons.SenderIdentity, -10);
                message.Seal(Commons.SenderKeypair.PrivateKey);
                message.Export();
            } catch (DateExpirationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");     
        }

        [TestMethod]
        public void ImportTest1()
        {   
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            string encoded = "M1.STEuZXlKemRXSWlPaUl4TkRRM09XSXdOeTB5TnpCa0xUUTJPRFF0WVRZMlppMWpaR0prT1Rrd1lUUTVaVElpTENKcGMzTWlPaUl4TkRRM09XSXdOeTB5TnpCa0xUUTJPRFF0WVRZMlppMWpaR0prT1Rrd1lUUTVaVElpTENKcFlYUWlPakUyTWpFNE1EQTBNVGNzSW1WNGNDSTZNVFkxTXpNek5qUXhOeXdpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFVWm1OalJPWmxWRVkxbElkMHhuV1RFeFdXMVNSQzh6UkM4NGRFTXdZVTh6Uld4U1owWm9SbnBFVGtVaWZRLnVSTDRFbVVyUFlXeXBHcDdQMjN6NUluMnNZQ3JtZlNTWDA0MVR0UmlpckFqVlRzYWY2ODRUR3Z5dzV4UUJCWGRtOUFzcnUvQkMzdDlxeUhBNE9heUJ3.eyJ1aWQiOiIxMTkwMjY0OS1kN2I2LTQxNjYtYWUxMS0zNzUxMjM0YTAwNjAiLCJzdWIiOiJlZjE4ZDYwZi05OWJkLTQ3YmMtYjdjMS1kZGQwMDBjZWVmNGYiLCJpc3MiOiIxNDQ3OWIwNy0yNzBkLTQ2ODQtYTY2Zi1jZGJkOTkwYTQ5ZTIiLCJpYXQiOjE2MjE4MDA0MTcsImV4cCI6MTkzNzE2MDQxN30.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.nPCPXBeZRedCtEGmrOXDSTowdR00MaWMENBQhg7X7qrcySvF7OeIEOvEteOqs0hhpA/5z6qS1bU6kviVriReDg";
            Message message = Message.Import(encoded);
            Assert.AreEqual(1, message.Profile);
            Assert.AreEqual(new Guid("6d51de7e-0755-4c05-9c20-ef32f0fc5710"), message.Id);
            Assert.AreEqual(new Guid("e945c60a-9987-4185-b2c0-61b7876180b1"), message.SubjectId);
            Assert.AreEqual(new Guid("ab5b8c0d-fd28-4c30-842f-347b48c86dbc"), message.IssuerId);
            Assert.AreEqual(Encoding.UTF8.GetBytes("Racecar is racecar backwards."), message.GetPayload());
            Assert.AreEqual(1621975130, message.IssuedAt);
            Assert.AreEqual(1653511130, message.ExpiresAt);
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
            string encoded = "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiI1ZWRkMmFkZS1mZjRiLTQ1YzktODMyMy1iOTE4YWJmYWZkMjEiLCJzdWIiOiJiMzIyNTU3NC1jYTNkLTRlYWItODNlMC03NjU1MDE2ZWEyMmQiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjE5NzU2MzAsImV4cCI6MTYyMTk3NTY0MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.Ci96jemhp5bsuwyEmbh8nKOwFa5YPnQ28+CqHfc3rfE4EOlQdAEGCrknctXsMv4FRoASwQy9P+yEjb4AF44aBA";
            try {
                Message message = Message.Import(encoded);
            } catch (DateExpirationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSealedTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Identity issuer = Commons.SenderIdentity;
            Message message = new Message(Guid.NewGuid(), issuer, 10);
            message.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsFalse(message.IsSealed);
            message.Seal(Commons.SenderKeypair.PrivateKey);
            Assert.IsTrue(message.IsSealed);
        }

        [TestMethod]
        public void GetPayloadTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Identity issuer = Commons.SenderIdentity;
            Message message1 = new Message(Guid.NewGuid(), issuer, 100);
            message1.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message1.GetPayload()));
            message1.Seal(Commons.SenderKeypair.PrivateKey);
            string encoded = message1.Export();
            Message message2 = Message.Import(encoded);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(message2.GetPayload()));
        }

        [TestMethod]
        public void LinkMessageTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Identity issuer = Commons.SenderIdentity;
            Identity receiver = Commons.ReceiverIdentity;
            Message issuerMessage = new Message(receiver.SubjectId, issuer, 100);
            issuerMessage.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            issuerMessage.Seal(Commons.SenderKeypair.PrivateKey);
            string issuerEncoded = issuerMessage.Export();
            
            Message receivedMessage = Message.Import(issuerEncoded);
            Message responseMessage = new Message(issuer.SubjectId, receiver, 100);
            responseMessage.AddPayload(Encoding.UTF8.GetBytes("It is!"));
            responseMessage.LinkMessage(receivedMessage);
            responseMessage.Seal(Commons.ReceiverKeypair.PrivateKey);
            string responseEncoded = responseMessage.Export();

            Message finalMessage = Message.Import(responseEncoded, issuerMessage);
        }

        [TestMethod]
        public void LinkMessageTest2()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Identity issuer = Commons.SenderIdentity;
            Identity receiver = Commons.ReceiverIdentity;
            Message issuerMessage1 = new Message(receiver.SubjectId, issuer, 100);
            issuerMessage1.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Message issuerMessage2 = new Message(receiver.SubjectId, issuer, 100);
            issuerMessage2.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            // TODO: something missing?
        }
 
    }

}