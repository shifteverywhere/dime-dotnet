//
//  EnvelopeTests.cs
//  DiME - Digital Identity Message Envelope
//  A secure and compact messaging format for assertion and practical use of digital identities
//
//  Released under the MIT licence, see LICENSE for more information.
//  Copyright © 2021 Shift Everywhere AB. All rights reserved.
//
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System;
using System.Text;
using System.Linq;
using ShiftEverywhere.DiME;

namespace ShiftEverywhere.DiMETest
{
    [TestClass]
    public class EnvelopeTests
    {

        [TestMethod]
        public void SealTest1()
        {
            Envelope envelope = new Envelope();
            try {
                envelope.Sign(Commons.SenderKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest2()
        {
            Envelope envelope = new Envelope(Commons.SenderIdentity.SubjectId);
            try {
                envelope.Sign(Commons.SenderKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest3()
        {
            Envelope envelope = new Envelope(Commons.SenderIdentity.SubjectId);
            envelope.AddItem(Commons.SenderKey);
            envelope.Sign(Commons.SenderKey);
        }

        [TestMethod]
        public void IIRExportTest1()
        {
            IdentityIssuingRequest iir = IdentityIssuingRequest.Generate(Key.Generate(KeyType.Identity));
            Envelope envelope = new Envelope();
            envelope.AddItem(iir);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IIRImportTest1()
        {
            string exported = "Di:IIR.eyJ1aWQiOiI5YzEwMzQ2Ni0wNThiLTRhYjgtYjcxZS0yYzZlNjUxYjU2MzgiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjA2OjMwLjY5NzIzNFoiLCJwdWIiOiJDWUh0Nmg2ZjdqcTJqbzVjc3g1dEFvenRpcU1BcXhqalRlcFBpZzJRd1pRRWdoS3RkUU41aEsiLCJjYXAiOlsiZ2VuZXJpYyJdfQ.ASq72ZmhWIrfze7Vjslh6WZMa5VS6uWmNnPUVbw/rBX4eaM96/8Pi82iiSDk62o1vIyFc5lsaYKFT1YQtLWjngs";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsTrue(envelope.IsAnonymous);
            Assert.IsNull(envelope.IssuerId);            
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(IdentityIssuingRequest), envelope.Items.ElementAt(0).GetType());
        }

        [TestMethod]
        public void IdentityExportTest1()
        {
            Envelope envelope = new Envelope(Commons.SenderIdentity.SubjectId);
            envelope.AddItem(Commons.SenderIdentity);
            envelope.Sign(Commons.SenderKey);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void IdentityExportTest2()
        {
            Envelope envelope = new Envelope();
            envelope.AddItem(Commons.SenderIdentity);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IdentityImportTest1()
        {
            string exported = "Di.eyJpc3MiOiJkMDBhZjBiNy04YWFlLTQ2YmEtYTMwOC0zZjMzYTg5ZGU0OGYiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjAzOjI0LjAxMTgzNVoifQ:ID.eyJ1aWQiOiIxNDg5NmMxZi1lZWYzLTRhM2MtOTdkNS1kZjEyZGRjNDA4NTgiLCJzdWIiOiJkMDBhZjBiNy04YWFlLTQ2YmEtYTMwOC0zZjMzYTg5ZGU0OGYiLCJpc3MiOiI0OTdkMTU2Ny1kMTBhLTRiNWYtOGIwOS00YmQ5NDc3ZTQyOTUiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjUyOjUyLjY0NDUzOFoiLCJleHAiOiIyMDIyLTA4LTA5VDA5OjUyOjUyLjY0NDUzOFoiLCJwdWIiOiJDWUh0ODIzMVl4VlR0Q3ZNa2VwWDRkS1lxcmU2YllNdjdyY3VKWkFSUGJjdWNSNDk5dEVobUoiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKMWFXUWlPaUkyWmpVek4yUXlZUzB3TWpKaUxUUmhNR1F0WWpVNFl5MHlNRFZqT1dRd01XRXpOelFpTENKemRXSWlPaUkwT1Rka01UVTJOeTFrTVRCaExUUmlOV1l0T0dJd09TMDBZbVE1TkRjM1pUUXlPVFVpTENKcGMzTWlPaUpoWXpZMFlXTm1aaTFrTXpCbUxUUXdNVEF0WWprMk5TMHpOVEZoTVRkbE1URTBOMllpTENKcFlYUWlPaUl5TURJeExUQTRMVEE1VkRBNU9qVXhPakkwTGpjM016azJPVm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE0VkRBNU9qVXhPakkwTGpjM016azJPVm9pTENKd2RXSWlPaUpEV1VoME4zSk5RV3Q2TVUxU1FrSjJRbkUwVFhOTVJWSnZRVVZpTjJSMlZ6STJXa05yTjFaVFZsWlZhRmRwWTFOcmNrSlNhVVFpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLkFRdFFuaUZ2My9mMXlod1p0ZjZxcCtoZVVpaW9sdlVnYUp3TzFMWjIrcTJydG1tWGtQNC9xenp0Vms5a1ZOZE1KYzRFdFVjTVlaOTEzWXJydEpudnpnWQ.AVlVdQY94UsYqpLwkeOgkbQi2vT+c/9XJF/rxl++epxDjiOwNkI3nom/9wZTq7U6297rQxWabM6udgwetHGG5As:Ac+l8VFO91/QUTHAnsVx9LW9D30pp8JYO9GHEPYejotRfhMAzCU35iJ8/wSopmqYSFKGvIR0Okd1rX0WmRXtgw0";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("d00af0b7-8aae-46ba-a308-3f33a89de48f"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-09T10:03:24.011835Z"), envelope.IssuedAt);          
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.SenderKey);
        }

        [TestMethod]
        public void IdentityImportTest2()
        {
            string exported = "Di:ID.eyJ1aWQiOiIxNDg5NmMxZi1lZWYzLTRhM2MtOTdkNS1kZjEyZGRjNDA4NTgiLCJzdWIiOiJkMDBhZjBiNy04YWFlLTQ2YmEtYTMwOC0zZjMzYTg5ZGU0OGYiLCJpc3MiOiI0OTdkMTU2Ny1kMTBhLTRiNWYtOGIwOS00YmQ5NDc3ZTQyOTUiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjUyOjUyLjY0NDUzOFoiLCJleHAiOiIyMDIyLTA4LTA5VDA5OjUyOjUyLjY0NDUzOFoiLCJwdWIiOiJDWUh0ODIzMVl4VlR0Q3ZNa2VwWDRkS1lxcmU2YllNdjdyY3VKWkFSUGJjdWNSNDk5dEVobUoiLCJjYXAiOlsiZ2VuZXJpYyIsImlkZW50aWZ5Il19.SUQuZXlKMWFXUWlPaUkyWmpVek4yUXlZUzB3TWpKaUxUUmhNR1F0WWpVNFl5MHlNRFZqT1dRd01XRXpOelFpTENKemRXSWlPaUkwT1Rka01UVTJOeTFrTVRCaExUUmlOV1l0T0dJd09TMDBZbVE1TkRjM1pUUXlPVFVpTENKcGMzTWlPaUpoWXpZMFlXTm1aaTFrTXpCbUxUUXdNVEF0WWprMk5TMHpOVEZoTVRkbE1URTBOMllpTENKcFlYUWlPaUl5TURJeExUQTRMVEE1VkRBNU9qVXhPakkwTGpjM016azJPVm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE0VkRBNU9qVXhPakkwTGpjM016azJPVm9pTENKd2RXSWlPaUpEV1VoME4zSk5RV3Q2TVUxU1FrSjJRbkUwVFhOTVJWSnZRVVZpTjJSMlZ6STJXa05yTjFaVFZsWlZhRmRwWTFOcmNrSlNhVVFpTENKallYQWlPbHNpWjJWdVpYSnBZeUlzSW1sa1pXNTBhV1o1SWl3aWFYTnpkV1VpWFgwLkFRdFFuaUZ2My9mMXlod1p0ZjZxcCtoZVVpaW9sdlVnYUp3TzFMWjIrcTJydG1tWGtQNC9xenp0Vms5a1ZOZE1KYzRFdFVjTVlaOTEzWXJydEpudnpnWQ.AVlVdQY94UsYqpLwkeOgkbQi2vT+c/9XJF/rxl++epxDjiOwNkI3nom/9wZTq7U6297rQxWabM6udgwetHGG5As";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsTrue(envelope.IsAnonymous);
            Assert.IsNull(envelope.IssuerId);            
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
            try {
                envelope.Verify(Commons.SenderKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void KeyExportTest1()
        {
            Envelope envelope = new Envelope(Commons.SenderIdentity.SubjectId);
            envelope.AddItem(Commons.SenderKey);
            envelope.Sign(Commons.SenderKey);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void KeyImportTest1()
        {
            string exported = "Di.eyJpc3MiOiJkMDBhZjBiNy04YWFlLTQ2YmEtYTMwOC0zZjMzYTg5ZGU0OGYiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjAxOjE0LjQ4MjEyN1oifQ:KEY.eyJraWQiOiJkMWJkNTUwMS02NGU5LTQwYjUtYTYwOC1hNGJiM2Q4MmViZTQiLCJpYXQiOiIyMDIxLTA4LTA5VDA5OjUyOjUyLjU0ODYyWiIsImtleSI6IkNZSGpZRTNUaEczeGJGQzVONkhkcHN5Mzdza0dkS1RIcHlWRzRWSnlYanVOeUJ4VEIzUHJnRyIsInB1YiI6IkNZSHQ4MjMxWXhWVHRDdk1rZXBYNGRLWXFyZTZiWU12N3JjdUpaQVJQYmN1Y1I0OTl0RWhtSiJ9:AXQfooJQ9BSq8aBeoDilZMebkypNqEESRb3fIBNUY/JYaw4+WFbVFXJNhp5ZouzutmS1QxzUeatZYdtgeZ1iMQ8";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("d00af0b7-8aae-46ba-a308-3f33a89de48f"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-09T10:01:14.482127Z"), envelope.IssuedAt);              
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Key), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.SenderKey);
        }

        [TestMethod]
        public void MessageExportTest1()
        {
            Envelope envelope = new Envelope(Commons.SenderIdentity.SubjectId);
            Message message = new Message(Commons.ReceiverIdentity.SubjectId, Commons.SenderIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.SenderKey);
            envelope.AddItem(message);
            envelope.Sign(Commons.SenderKey);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void MessageImportTest1()
        {
            string exported = "Di.eyJpc3MiOiJkMDBhZjBiNy04YWFlLTQ2YmEtYTMwOC0zZjMzYTg5ZGU0OGYiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjMzOjUzLjU2NjA5MloifQ:MSG.eyJ1aWQiOiJmNDVjZTgxMC0yOWZiLTQyMDgtOTQyMy03MzNlNjUzYTc5MmMiLCJhdWQiOiIyZDIyNGZlYy0zNjZmLTQyODQtYTgyMi0wYTVmZjA0ZTcxMWQiLCJpc3MiOiJkMDBhZjBiNy04YWFlLTQ2YmEtYTMwOC0zZjMzYTg5ZGU0OGYiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjMzOjUzLjU2OTk3NloiLCJleHAiOiIyMDIxLTA4LTA5VDEwOjM1OjMzLjU2OTk3NloifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.ARKIPPfOolEwhKxWNPkFhPregIGeu9L4mHpvE8NbCPDpS8NohtidnZZmnW0c5bgMTBpNwurvl+c/IZQ5gJ9sFwo:ASo99mYF/87/Bb2Eb2pDG3ugL+9UAmbjxJx7Wp6gi7qjFDF37dwiZZ58n+2wkGc5EnAnyssrADSyfGt2/KlcrwM";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("d00af0b7-8aae-46ba-a308-3f33a89de48f"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-09T10:33:53.566092Z"), envelope.IssuedAt);              
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Message), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.SenderKey);
        }

        [TestMethod]
        public void ExportTest1()
        {
            Envelope envelope1 = new Envelope(Commons.SenderIdentity.SubjectId);
            envelope1.AddItem(Commons.SenderIdentity);
            envelope1.AddItem(Commons.SenderKey.PublicCopy());
            envelope1.Sign(Commons.SenderKey);
            string exported = envelope1.Export();

            Envelope envelope2 = Envelope.Import(exported);
            envelope2.Verify(Commons.SenderKey);
            Assert.AreEqual(2, envelope2.Items.Count);

            Identity identity = (Identity)envelope2.Items.ElementAt(0);
            Assert.AreEqual(Commons.SenderIdentity.SubjectId, identity.SubjectId);
            Key keybox = (Key)envelope2.Items.ElementAt(1);
            Assert.AreEqual(Commons.SenderKey.UniqueId, keybox.UniqueId);
            Assert.IsNull(keybox.Secret);
        }

    }

}
