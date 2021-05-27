using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class EnvelopeTests
    {
        [TestMethod]
        public void EnvelopeTest1()
        {
            int profile = 1;
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10, profile);
            Assert.IsTrue(1 == envelope.Profile);
            Assert.IsNotNull(envelope.Id);
            Assert.AreEqual(Commons.SenderIdentity.SubjectId, envelope.IssuerId);
            Assert.AreEqual(Commons.ReceiverIdentity.SubjectId, envelope.SubjectId);
            Assert.IsTrue(envelope.IssuedAt >= now && envelope.IssuedAt <= (now + 1));
            Assert.IsTrue(envelope.ExpiresAt >= (now + 10) && envelope.ExpiresAt <= (now + 11));         
        }

        [TestMethod]
        public void ExportTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            envelope.Seal(Commons.SenderKeypair.PrivateKey);
            string encoded = envelope.Export();
            Assert.IsNotNull(encoded);
            Assert.IsTrue(encoded.Length > 0);
            Assert.IsTrue(encoded.StartsWith("E" + envelope.Profile.ToString()));
            Assert.IsTrue(encoded.Split(new char[] { '.' }).Length == 5);          
        }

        [TestMethod]
        public void ExportTest2()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            try {
                envelope.Export();
            } catch(IntegrityException) { } // All is well
        }

        [TestMethod]
        public void ExportTest3()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            envelope.Seal(Commons.SenderKeypair.PrivateKey);
            envelope.Export();
            try {
                envelope.ExpiresAt = envelope.ExpiresAt + 100;
                envelope.Export();
            } catch(IntegrityException) { } // All is well
        }

        [TestMethod]
        public void SealTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            try {
                envelope.Seal(Commons.SenderKeypair.PrivateKey);
            } catch(ArgumentException) { return; } // All is well
        }

        [TestMethod]
        public void SealTest2()
        {  
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            try {
                envelope.Seal(Commons.ReceiverKeypair.PrivateKey);
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }


        [TestMethod]
        public void SealTest3()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Message message = GetMessage("Racecar is racecar backwards.");
            Message response = GetResponse("It is!", message);
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 120);
            envelope.AddMessage(message);
            envelope.AddMessage(response);
            envelope.Seal(Commons.SenderKeypair.PrivateKey);
        } 

        [TestMethod]
        public void ImportTest1()
        {  
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            string encoded = "E1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.TTEuU1RFdVpYbEtlbVJYU1dsUGFVcG9XV3BXYVU5SFRYZGFRekZ0V2tSSk5FeFVVbXBOZWtGMFQwUlJlVnBwTUhwT1JHUnBUa1JvYWs5RVdtdFpiVTFwVEVOS2NHTXpUV2xQYVVrelRWZFZlVmx0VlRGWmVUQXpUVmRXYTB4VVVYbFphbEYwV1cxWk5VMXBNRFJhYlVwcFdtMVZNazFxUVROT01rMXBURU5LY0ZsWVVXbFBha1V5VFdwRk5VNTZTWGROYWxGelNXMVdOR05EU1RaTlZGa3hUWHBWZDA5RVFYbE9RM2RwWVZkME5VbHFiMmxVVlU1MlpEQktVbGRWVWt4TmJGb3pVVmhzUmxGWGJGUmtSMUl4VTI1d2QyUlZkSEZqTUhSTFRsWjRNVTFFUVhsUmJUVlFUMVZTTUZJd1RrOVRNWEJwWTBaQ1IxUlVWbEJPUmxKRlVucE5NVk13VmtsYWVVbHpTVzFPYUdORFNUWlhlVXBvWkZoU2IySXpTbkJsYlZWcFdGZ3dMbmREVjIweFQzRXhNSEZWSzNoUFlWWlZUVEp3UjFkSFVtUXhha2d4YzJGV1lYUkdNVWMyWnk5M1VGVXlTSFk1ZEdGU1dHaElOR3RXVldjME5uRmpjVTB5VFRSS2QwSlZabTh4YldNMmRVMTBaMUpPU2tKUi5leUoxYVdRaU9pSmxNRGd4TXpVMk1pMW1aR0ZsTFRRMVl6WXRPR1JtTmkxaE9HSmtNV00zTnpJeVpUZ2lMQ0p6ZFdJaU9pSm1OREl5T1RVek1pMWhNelV5TFRRM05qZ3RPV0k0WWkxaE5UWTBZemRqWWpKalpEWWlMQ0pwYzNNaU9pSmhZalZpT0dNd1pDMW1aREk0TFRSak16QXRPRFF5Wmkwek5EZGlORGhqT0Raa1ltTWlMQ0pwWVhRaU9qRTJNakl3TlRnek1ESXNJbVY0Y0NJNk1UWTFNelU1TkRNd01uMC5VbUZqWldOaGNpQnBjeUJ5WVdObFkyRnlJR0poWTJ0M1lYSmtjeTQuVkg5NzVzOXd0Mk5xSHdjRWIvclM4SWdFN3MxZk9BaTBFOUhMQUNQc254Mnp3RzJlZ1hkbVlMUi9jZGozbDhFMktFdVpwTzhCblJJa0lNWFZCRjE3Q2c.eyJ1aWQiOiI0ZDIzNjJkNy1kNjA0LTQ3NzAtOWMyOC1hYTcxYWVmZmU3NzUiLCJzdWIiOiJmNDIyOTUzMi1hMzUyLTQ3NjgtOWI4Yi1hNTY0YzdjYjJjZDYiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjIwNTgzMDIsImV4cCI6MTY1MzU5NDMwMn0.Y9H36yfocAJOFIBYyw9Ix1O/uA9DueoKTmD1BoNsFg0eSvRfBljcaoC7m+Rd2HJa3Xd3idMqpdwce9mOGy0vDA";
            Envelope envelope = Envelope.Import(encoded);
            Assert.AreEqual(new Guid("4d2362d7-d604-4770-9c28-aa71aeffe775"), envelope.Id);
            Assert.AreEqual(new Guid("f4229532-a352-4768-9b8b-a564c7cb2cd6"), envelope.SubjectId);
            Assert.AreEqual(new Guid("ab5b8c0d-fd28-4c30-842f-347b48c86dbc"), envelope.IssuerId);
            Assert.AreEqual(1622058302, envelope.IssuedAt);
            Assert.AreEqual(1653594302, envelope.ExpiresAt);
            Assert.IsNotNull(envelope.Identity);
            Assert.IsNotNull(envelope.Messages);
        }

        [TestMethod]
        public void ImportTest2()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            string encoded = "E1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.TTEuU1RFdVpYbEtlbVJYU1dsUGFVcG9XV3BXYVU5SFRYZGFRekZ0V2tSSk5FeFVVbXBOZWtGMFQwUlJlVnBwTUhwT1JHUnBUa1JvYWs5RVdtdFpiVTFwVEVOS2NHTXpUV2xQYVVrelRWZFZlVmx0VlRGWmVUQXpUVmRXYTB4VVVYbFphbEYwV1cxWk5VMXBNRFJhYlVwcFdtMVZNazFxUVROT01rMXBURU5LY0ZsWVVXbFBha1V5VFdwRk5VNTZTWGROYWxGelNXMVdOR05EU1RaTlZGa3hUWHBWZDA5RVFYbE9RM2RwWVZkME5VbHFiMmxVVlU1MlpEQktVbGRWVWt4TmJGb3pVVmhzUmxGWGJGUmtSMUl4VTI1d2QyUlZkSEZqTUhSTFRsWjRNVTFFUVhsUmJUVlFUMVZTTUZJd1RrOVRNWEJwWTBaQ1IxUlVWbEJPUmxKRlVucE5NVk13VmtsYWVVbHpTVzFPYUdORFNUWlhlVXBvWkZoU2IySXpTbkJsYlZWcFdGZ3dMbmREVjIweFQzRXhNSEZWSzNoUFlWWlZUVEp3UjFkSFVtUXhha2d4YzJGV1lYUkdNVWMyWnk5M1VGVXlTSFk1ZEdGU1dHaElOR3RXVldjME5uRmpjVTB5VFRSS2QwSlZabTh4YldNMmRVMTBaMUpPU2tKUi5leUoxYVdRaU9pSmpZamd5TVdVNE15MHdaV0l4TFRSbVlUQXRZVGc0TUMweU5HVXpaREl6WmpRMlltSWlMQ0p6ZFdJaU9pSm1OREl5T1RVek1pMWhNelV5TFRRM05qZ3RPV0k0WWkxaE5UWTBZemRqWWpKalpEWWlMQ0pwYzNNaU9pSmhZalZpT0dNd1pDMW1aREk0TFRSak16QXRPRFF5Wmkwek5EZGlORGhqT0Raa1ltTWlMQ0pwWVhRaU9qRTJNakl3TlRrek9URXNJbVY0Y0NJNk1UWXlNakExT1RRd01YMC5VbUZqWldOaGNpQnBjeUJ5WVdObFkyRnlJR0poWTJ0M1lYSmtjeTQuV3VKMTRkY0d3bmJwamFiYjkwOHA2SVdCTGdoS3d2REhWRzNoc1dQV3Q1ZFVVQjNub2JwLzBPUHJUM09VcitENHhEemtBcXpvRUVQM2cyeUNCU2djQ1E.eyJ1aWQiOiI1YTdmY2ZmZS01NGRhLTQwZDQtOGY2My1hMDA5MmIwNTdkOWMiLCJzdWIiOiJmNDIyOTUzMi1hMzUyLTQ3NjgtOWI4Yi1hNTY0YzdjYjJjZDYiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjIwNTkzOTEsImV4cCI6MTYyMjA1OTQwMX0.Zz+c1e3H2jrdqmhzoacUnrr3Wz1KaR//JRLQeEmQ4hmQrSszwg/vEvYZo+3KK4xl/cNh2A2YOyXwzD+o8Lm/Aw";
            try {
                Envelope.Import(encoded);
            } catch (DateExpirationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void ImportTest3()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            string encoded = "M1.STEuZXlKemRXSWlPaUpoWWpWaU9HTXdaQzFtWkRJNExUUmpNekF0T0RReVppMHpORGRpTkRoak9EWmtZbU1pTENKcGMzTWlPaUkzTVdVeVltVTFZeTAzTVdWa0xUUXlZalF0WW1ZNU1pMDRabUppWm1VMk1qQTNOMk1pTENKcFlYUWlPakUyTWpFNU56SXdNalFzSW1WNGNDSTZNVFkxTXpVd09EQXlOQ3dpYVd0NUlqb2lUVU52ZDBKUldVUkxNbFozUVhsRlFXbFRkR1IxU25wd2RVdHFjMHRLTlZ4MU1EQXlRbTVQT1VSMFIwTk9TMXBpY0ZCR1RUVlBORlJFUnpNMVMwVklaeUlzSW1OaGNDSTZXeUpoZFhSb2IzSnBlbVVpWFgwLndDV20xT3ExMHFVK3hPYVZVTTJwR1dHUmQxakgxc2FWYXRGMUc2Zy93UFUySHY5dGFSWGhINGtWVWc0NnFjcU0yTTRKd0JVZm8xbWM2dU10Z1JOSkJR.eyJ1aWQiOiI1ZWRkMmFkZS1mZjRiLTQ1YzktODMyMy1iOTE4YWJmYWZkMjEiLCJzdWIiOiJiMzIyNTU3NC1jYTNkLTRlYWItODNlMC03NjU1MDE2ZWEyMmQiLCJpc3MiOiJhYjViOGMwZC1mZDI4LTRjMzAtODQyZi0zNDdiNDhjODZkYmMiLCJpYXQiOjE2MjE5NzU2MzAsImV4cCI6MTYyMTk3NTY0MH0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.Ci96jemhp5bsuwyEmbh8nKOwFa5YPnQ28+CqHfc3rfE4EOlQdAEGCrknctXsMv4FRoASwQy9P+yEjb4AF44aBA";
            try {
                Envelope.Import(encoded);
            } catch (DataFormatException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void IsSealedTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            Assert.IsFalse(envelope.IsSealed);
            envelope.Seal(Commons.SenderKeypair.PrivateKey);
            Assert.IsTrue(envelope.IsSealed);
        }

        [TestMethod]
        public void IdTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 10);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            envelope.Seal(Commons.SenderKeypair.PrivateKey);
            Guid uid1 = envelope.Id;
            envelope.ExpiresAt = envelope.ExpiresAt + 100;
            Assert.AreNotEqual(uid1, envelope.Id);
        }

        [TestMethod]
        public void AddMessageTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope1 = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 100);
            envelope1.AddMessage(GetMessage("Racecar is racecar backwards."));
            envelope1.Seal(Commons.SenderKeypair.PrivateKey);
            string encoded = envelope1.Export();

            Envelope envelope2 = Envelope.Import(encoded);
            Assert.AreEqual("Racecar is racecar backwards.", System.Text.Encoding.UTF8.GetString(envelope2.Messages[0].GetPayload()));
        }  

        [TestMethod]
        public void VerifyTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 100);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            try {
                envelope.Verify(false);
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen");
        }

        [TestMethod]
        public void ThumbprintTest1()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope1 = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 120);
            envelope1.AddMessage(GetMessage("Racecar is racecar backwards."));
            envelope1.Seal(Commons.SenderKeypair.PrivateKey);
            string thumbprint1 = envelope1.Thumbprint();
            string encoded = envelope1.Export();
            Envelope envelope2 = Envelope.Import(encoded);
            string thumbprint2 = envelope2.Thumbprint();
            Assert.AreEqual(thumbprint1, thumbprint2);
        }

        [TestMethod]
        public void ThumbprintTest2()
        {   
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Message message = GetMessage("Racecar is racecar backwards.");
            Envelope envelope1 = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 120);
            envelope1.AddMessage(message);
            envelope1.Seal(Commons.SenderKeypair.PrivateKey);
            Envelope envelope2 = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 120);
            envelope2.AddMessage(message);
            envelope2.Seal(Commons.SenderKeypair.PrivateKey);
            Assert.AreNotEqual(envelope1.Thumbprint(), envelope2.Thumbprint());
        }

        [TestMethod]
        public void ThumbprintTest3()
        {
            Identity.TrustedIdentity = Commons.TrustedIdentity;
            Envelope envelope = new Envelope(Commons.SenderIdentity, Commons.ReceiverIdentity.SubjectId, 120);
            envelope.AddMessage(GetMessage("Racecar is racecar backwards."));
            try {
                envelope.Thumbprint();
            } catch (IntegrityException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        #region -- PRIVATE --
        private Message GetMessage(string payload)
        {
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity, 120);
            message.SetPayload(Encoding.UTF8.GetBytes(payload));
            message.Seal(Commons.SenderKeypair.PrivateKey);
            return message;
        }

        private Message GetResponse(string payload, Message linkedMessage = null)
        {
            Message message = new Message(Commons.SenderIdentity.SubjectId, Commons.ReceiverIdentity, 120);
            message.SetPayload(Encoding.UTF8.GetBytes(payload));
            if (linkedMessage != null)
            {
                message.LinkMessage(linkedMessage);
            }
            message.Seal(Commons.ReceiverKeypair.PrivateKey);
            return message;
        }
        #endregion

    }

}