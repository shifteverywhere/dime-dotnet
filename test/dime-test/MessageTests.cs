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
            this.SetTrustedIdentity();
            int profile = 1;
            Guid subjectId = Guid.NewGuid();
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity, profile);
            Identity issuer = this.GetIdentity(keypair);
            byte[] payload = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Message message = new Message(subjectId, issuer, 10);
            message.AddPayload(payload);
            Assert.IsTrue(1 == message.Profile);
            Assert.IsNotNull(message.Id);
            Assert.AreEqual(subjectId, message.SubjectId);
            Assert.AreEqual(issuer.identityKey, message.Identity.identityKey);
            Assert.AreEqual(payload, message.GetPayload());
            Assert.IsTrue(message.IssuedAt >= now && message.IssuedAt <= (now + 1));
            Assert.IsTrue(message.ExpiresAt >= (now + 10) && message.ExpiresAt <= (now + 10));
        }

        [TestMethod]
        public void MessageTest2()
        {
            this.SetTrustedIdentity();
            Guid subjectId = Guid.NewGuid();
            Identity issuer = this.GetIdentity(Keypair.GenerateKeypair(KeypairType.Identity));
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
            this.SetTrustedIdentity();
            Identity identity = this.GetIdentity(Keypair.GenerateKeypair(KeypairType.Identity));
            try {
                Message message = new Message(Guid.NewGuid(), null, 10);
            } catch (NullReferenceException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");         
        }

        [TestMethod]
        public void MessageTest4()
        {
            this.SetTrustedIdentity();
            try{
                Message message = new Message(Guid.NewGuid(), this.GetIdentity(Keypair.GenerateKeypair(KeypairType.Identity)), -10);
            } catch (DateExpirationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");     
        }

        [TestMethod]
        public void MessageExport1()
        {  
            this.SetTrustedIdentity();
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Message message = new Message(Guid.NewGuid(), this.GetIdentity(keypair), 10);
            string encoded = message.Export(keypair.PrivateKey);
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("M" + message.Profile.ToString()));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 5);          
        }  

        [TestMethod]
        public void MessageExport2()
        {  
            this.SetTrustedIdentity();
            Message message = new Message(Guid.NewGuid(), this.GetIdentity(Keypair.GenerateKeypair(KeypairType.Identity)), 10);
            try {
                message.Export();
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }  

        [TestMethod]
        public void MessageExport3()
        {  
            this.SetTrustedIdentity();
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Message message = new Message(Guid.NewGuid(), this.GetIdentity(keypair), 10);
            message.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Export(keypair.PrivateKey);
            message.Export();
        }

        [TestMethod]
        public void MessageImport1()
        {   
            // TODO: need a static trusted identity to work
            /*
            string encoded = "M1.STEuZXlKemRXSWlPaUl4TkRRM09XSXdOeTB5TnpCa0xUUTJPRFF0WVRZMlppMWpaR0prT1Rrd1lUUTVaVElpTENKcGMzTWlPaUl4TkRRM09XSXdOeTB5TnpCa0xUUTJPRFF0WVRZMlppMWpaR0prT1Rrd1lUUTVaVElpTENKcFlYUWlPakUyTWpFNE1EQTBNVGNzSW1WNGNDSTZNVFkxTXpNek5qUXhOeXdpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFVWm1OalJPWmxWRVkxbElkMHhuV1RFeFdXMVNSQzh6UkM4NGRFTXdZVTh6Uld4U1owWm9SbnBFVGtVaWZRLnVSTDRFbVVyUFlXeXBHcDdQMjN6NUluMnNZQ3JtZlNTWDA0MVR0UmlpckFqVlRzYWY2ODRUR3Z5dzV4UUJCWGRtOUFzcnUvQkMzdDlxeUhBNE9heUJ3.eyJ1aWQiOiIxMTkwMjY0OS1kN2I2LTQxNjYtYWUxMS0zNzUxMjM0YTAwNjAiLCJzdWIiOiJlZjE4ZDYwZi05OWJkLTQ3YmMtYjdjMS1kZGQwMDBjZWVmNGYiLCJpc3MiOiIxNDQ3OWIwNy0yNzBkLTQ2ODQtYTY2Zi1jZGJkOTkwYTQ5ZTIiLCJpYXQiOjE2MjE4MDA0MTcsImV4cCI6MTkzNzE2MDQxN30.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.nPCPXBeZRedCtEGmrOXDSTowdR00MaWMENBQhg7X7qrcySvF7OeIEOvEteOqs0hhpA/5z6qS1bU6kviVriReDg";
            Message message = Message.Import(encoded);
            Assert.AreEqual(1, message.profile);
            Assert.AreEqual(new Guid("11902649-d7b6-4166-ae11-3751234a0060"), message.id);
            Assert.AreEqual(new Guid("ef18d60f-99bd-47bc-b7c1-ddd000ceef4f"), message.subjectId);
            Assert.AreEqual(new Guid("14479b07-270d-4684-a66f-cdbd990a49e2"), message.issuerId);
            Assert.AreEqual(Encoding.UTF8.GetBytes("Racecar is racecar backwards."), message.GetPayload());
            Assert.AreEqual(1621800417, message.issuedAt);
            Assert.AreEqual(1937160417, message.expiresAt);
            Assert.IsNull(message.state);
            Assert.IsNotNull(message.identity);
            Assert.AreEqual(message.issuerId, message.identity.subjectId);
            Assert.AreEqual(new Guid("14479b07-270d-4684-a66f-cdbd990a49e2"), message.identity.issuerId);
            Assert.AreEqual(1621800417, message.identity.issuedAt);
            Assert.AreEqual(1653336417, message.identity.expiresAt);
            Assert.AreEqual("MCowBQYDK2VwAyEAFf64NfUDcYHwLgY11YmRD/3D/8tC0aO3ElRgFhFzDNE", message.identity.identityKey);
            */
        } 

        [TestMethod]
        public void MessageImport2()
        {  
            // TODO: need a static trusted identity to work
            /*
            string encoded = "M1.STEuZXlKemRXSWlPaUprTVRrd05HSTJOeTFsT0dSbExUUTRZVEl0T1RJNE5pMWlZell4WlRKaE9HWmxNaklpTENKcGMzTWlPaUprTVRrd05HSTJOeTFsT0dSbExUUTRZVEl0T1RJNE5pMWlZell4WlRKaE9HWmxNaklpTENKcFlYUWlPakUyTWpFNE1EQTBOakFzSW1WNGNDSTZNVFkxTXpNek5qUTJNQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFVZDViUzlyTlhkY2RUQXdNa0pEZDNWTVpXUnlaSEJUT1U0ME9IZE9ZMDlWY21zM1MycEtOVEo1Y1RONmVUbFJTU0o5Lk1vajE2ZjVwT2VsenhmYUFlTWNtVDZRNnZHdVQ1Ti96aVlqcjJGVjhlWStzOGRMay9ZRnFhMTQ4MWJmZStFcmhXd2ZJU2djUFVEaVRIeGQ2a0x4aUJB.eyJ1aWQiOiJiNmUwNGYxNC1jYzE1LTQzN2QtYTc1Ni1jNTJhYTNiNjk0NTYiLCJzdWIiOiI1Njk1N2NhNS0zOGEzLTQ0YTAtYTNkYS1mZTE3ZmM2NTQzNjEiLCJpc3MiOiJkMTkwNGI2Ny1lOGRlLTQ4YTItOTI4Ni1iYzYxZTJhOGZlMjIiLCJpYXQiOjE2MjE4MDA0NjAsImV4cCI6MTYyMTgwMDQ3MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.Tt4T8XmMqQcl3E5FdYCsqXie3VruuTSGK4UvIIJtTVyAzHQyRcJM6KnMf7vtGV2oI9kshcxFtAksSYg3PQy8AA";
            try {
                Message message = Message.Import(encoded);
            } catch (DateExpirationException) { /* All is well *//* }
            */
        }

        [TestMethod]
        public void MessageHasSignatureTest1()
        {
            this.SetTrustedIdentity();
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Identity issuer = this.GetIdentity(keypair);
            Message message = new Message(Guid.NewGuid(), issuer, 10);
            message.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Assert.IsFalse(message.IsSealed);
            message.Seal(keypair.PrivateKey);
            Assert.IsTrue(message.IsSealed);
        }

        [TestMethod]
        public void MessageGetPayloadTest1()
        {
            this.SetTrustedIdentity();
            Keypair keypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Identity issuer = this.GetIdentity(keypair);
            byte[] payload = Encoding.UTF8.GetBytes("Racecar is racecar backwards.");
            Message message = new Message(Guid.NewGuid(), issuer, 10);
            message.AddPayload(payload);
            Assert.AreEqual(payload, message.GetPayload());
            message.Export(keypair.PrivateKey);
            Assert.AreEqual(payload, message.GetPayload());
        }

        [TestMethod]
        public void MessageLinkMessageTest1()
        {
            this.SetTrustedIdentity();
            Keypair issuerKeypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Identity issuer = this.GetIdentity(issuerKeypair);
            Keypair receiverKeypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Identity receiver = this.GetIdentity(receiverKeypair);
            Message issuerMessage = new Message(receiver.SubjectId, issuer, 100);
            issuerMessage.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            string issuerEncoded = issuerMessage.Export(issuerKeypair.PrivateKey);
            
            Message receivedMessage = Message.Import(issuerEncoded);
            Message responseMessage = new Message(issuer.SubjectId, receiver, 100);
            responseMessage.AddPayload(Encoding.UTF8.GetBytes("It is!"));
            responseMessage.LinkMessage(receivedMessage);
            string responseEncoded = responseMessage.Export(receiverKeypair.PrivateKey);

            Message finalMessage = Message.Import(responseEncoded, issuerMessage);
        }

        public void MessageLinkMessageTest2()
        {
            Keypair issuerKeypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Identity issuer = this.GetIdentity(issuerKeypair);
            Keypair receiverKeypair = Keypair.GenerateKeypair(KeypairType.Identity);
            Identity receiver = this.GetIdentity(receiverKeypair);
            Message issuerMessage1 = new Message(receiver.SubjectId, issuer, 100);
            issuerMessage1.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            Message issuerMessage2 = new Message(receiver.SubjectId, issuer, 100);
            issuerMessage2.AddPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));

        }

        #region -- PRIVATE --
        private Identity trustedIdentity;
        private Keypair trustedKeypair;
        private void SetTrustedIdentity()
        {
            if ( this.trustedIdentity == null)
            {
                Identity.Capability[] caps = new Identity.Capability[2] { Identity.Capability.Issue, Identity.Capability.Authorize };
                this.trustedKeypair = Keypair.GenerateKeypair(KeypairType.Identity);
                this.trustedIdentity = Identity.IssueIdentity(IdentityIssuingRequest.GenerateRequest(this.trustedKeypair, caps), Guid.NewGuid(), caps, this.trustedKeypair);
            }
            Identity.TrustedIdentity = this.trustedIdentity;
        }
        private Identity GetIdentity(Keypair keypair)
        {
            Identity.Capability[] caps = new Identity.Capability[1] { Identity.Capability.Authorize };
            return Identity.IssueIdentity(IdentityIssuingRequest.GenerateRequest(keypair), Guid.NewGuid(), caps, this.trustedKeypair, Identity.TrustedIdentity);
        }
        #endregion
        
    }

}