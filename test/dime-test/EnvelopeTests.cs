//
//  EnvelopeTests.cs
//  Di:ME - Digital Identity Message Envelope
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
                envelope.Sign(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest2()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            try {
                envelope.Sign(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void SealTest3()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
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
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerIdentity);
            envelope.Sign(Commons.IssuerKey);
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
            envelope.AddItem(Commons.IssuerIdentity);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 2);
        }

        [TestMethod]
        public void IdentityImportTest1()
        {
            string exported = "Di.eyJpc3MiOiI2MDY2OTQ1My1jNGQ5LTQ2MjgtODg4MC05NmM0YmUyNWQzY2UiLCJpYXQiOiIyMDIxLTA4LTA5VDE4OjM5OjUxLjY4MzM1OFoifQ:ID.eyJ1aWQiOiJlY2EzOWFiYS00YzY5LTQ4YjItYTliZS0wYzQxNmZlMDgwZDciLCJzdWIiOiI2MDY2OTQ1My1jNGQ5LTQ2MjgtODg4MC05NmM0YmUyNWQzY2UiLCJpc3MiOiJmNjhkMTVhYy04MjJkLTRmZGMtODFjYy04ZTUwYjQ3ODc3MmUiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjUzOjIyLjUxNTM0MloiLCJleHAiOiIyMDIyLTA4LTA5VDEwOjUzOjIyLjUxNTM0MloiLCJwdWIiOiIxaFBKdWRHUndrNkU2a1dKWXJYQjlBOXJoUWNUYmdGaFo2NVJTWXZMTktHUGdQUW5ZbjRjOCIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKMWFXUWlPaUl5T1RCa01XUm1ZaTB3TVdJMExUUXpPVFV0WW1FMVlpMWlObUkwTURGa1lXVXlNVFFpTENKemRXSWlPaUptTmpoa01UVmhZeTA0TWpKa0xUUm1aR010T0RGall5MDRaVFV3WWpRM09EYzNNbVVpTENKcGMzTWlPaUpqWTJVNU16azBNQzFoWm1OaUxUUmhZVEV0T1RBMk15MW1NR1l3WVRZellUVmxaREFpTENKcFlYUWlPaUl5TURJeExUQTRMVEE1VkRFd09qVXlPak16TGpBd056SXpPRm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE0VkRFd09qVXlPak16TGpBd056SXpPRm9pTENKd2RXSWlPaUl4YUZCS1NGazNhMk5aVlhSdGVIVmlRbU5CV0daS1dHOTVTMk54V0V3elJuTkVWVVJ1Vm10aVIwcG9VSGw1UzJoV2JsSnBWU0lzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpTENKcGMzTjFaU0pkZlEuQVZXNFh4dVcyTWYrdVd4dG8zYmZpbGZhVi9FQWRMWVhnL3V6aW5pTFhKOFZQUDQveFNSTmVRYVQrcjJKQmY2WHFkK0JJTmdDbGNCTmhReDNxZU9xREFv.AUIHWWvs5nuQuXsJ396vh8HbtvVElJqXQO+GixI2ZStdzO+Wgw7/mIURS0c/t3hBvUNgb8hnrG8fC3iFIY/sFgM:AWygDUfDPiQkIKDLWnobIWJLEis+3xhKpSn9m3roUCAPD+YxhkeY0mK/EMc0QlGd0I3NKT5ALEGA8Xngqw3NrgA";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("60669453-c4d9-4628-8880-96c4be25d3ce"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-09T18:39:51.683358Z"), envelope.IssuedAt);          
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
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
                envelope.Verify(Commons.IssuerKey);
            } catch (InvalidOperationException) { return; } // All is well
            Assert.IsTrue(false, "Should not happen.");
        }

        [TestMethod]
        public void KeyExportTest1()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope.AddItem(Commons.IssuerKey);
            envelope.Sign(Commons.IssuerKey);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void KeyImportTest1()
        {
            string exported = "Di.eyJpc3MiOiI2MDY2OTQ1My1jNGQ5LTQ2MjgtODg4MC05NmM0YmUyNWQzY2UiLCJpYXQiOiIyMDIxLTA4LTA5VDExOjAzOjU2LjkyNTc1MVoifQ:KEY.eyJ1aWQiOiJhZDBmZmQwMi0yMjE1LTQ4NTktOGYwZC0xMTcxNzU0Njg3MjIiLCJpYXQiOiIyMDIxLTA4LTA5VDEwOjUzOjIyLjQyMzExNFoiLCJrZXkiOiIxaEVqMWRpc01yTUNFVURZM05SVnZMc2FaVWpaZlFUWmNCZ0FDRXV0UExDWXF2eGVCUTVTeiIsInB1YiI6IjFoUEp1ZEdSd2s2RTZrV0pZclhCOUE5cmhRY1RiZ0ZoWjY1UlNZdkxOS0dQZ1BRblluNGM4In0:AfCjBGuZavJmztFe+ZodvETQD3qAkrlkWxjMb+cQ1747lO/2aVgNvpNQosrRYbimIm3IudFC4hNArE0hrPUJuQ4";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("60669453-c4d9-4628-8880-96c4be25d3ce"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-09T11:03:56.925751Z"), envelope.IssuedAt);              
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Key), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void MessageExportTest1()
        {
            Envelope envelope = new Envelope(Commons.IssuerIdentity.SubjectId);
            Message message = new Message(Commons.AudienceIdentity.SubjectId, Commons.IssuerIdentity.SubjectId, 100);
            message.SetPayload(Encoding.UTF8.GetBytes("Racecar is racecar backwards."));
            message.Sign(Commons.IssuerKey);
            envelope.AddItem(message);
            envelope.Sign(Commons.IssuerKey);
            string exported = envelope.Export();
            Assert.IsNotNull(exported);
            Assert.IsTrue(exported.Length > 0);
            Assert.IsTrue(exported.StartsWith(Envelope.HEADER));
            Assert.IsTrue(exported.Split(new char[] { ':' }).Length == 3);
        }

        [TestMethod]
        public void MessageImportTest1()
        {
            string exported = "Di.eyJpc3MiOiI2MDY2OTQ1My1jNGQ5LTQ2MjgtODg4MC05NmM0YmUyNWQzY2UiLCJpYXQiOiIyMDIxLTA4LTA5VDExOjAxOjM5Ljc1MDk4NFoifQ:MSG.eyJ1aWQiOiIwN2ZmYzcyOC1jZjMyLTRhMzAtOGIwNS01NDZiNjBmNzNmYTYiLCJhdWQiOiI0ZDAzMTM1Zi0wZTBkLTQ4YjYtYTQ0Ny01ZDM1YmU3ODE5ZjkiLCJpc3MiOiI2MDY2OTQ1My1jNGQ5LTQ2MjgtODg4MC05NmM0YmUyNWQzY2UiLCJpYXQiOiIyMDIxLTA4LTA5VDExOjAxOjM5Ljc1NDk0OFoiLCJleHAiOiIyMDIxLTA4LTA5VDExOjAzOjE5Ljc1NDk0OFoifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.AWp544tadH0Nnds+dKf3P0LwkO5sCyacQaKsoeNJ6thm8IHqaJo1ZIV4YhhUv0iIHogrVskwTKYI83Sztw//hAM:AXpnsIDHyzJcATxDEC0jFAGA25hqarfsipAk8vUjBDCBaLsmdk4f83/h+psPRlemsXd441vTHDs0zWs8P21AJA8";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("60669453-c4d9-4628-8880-96c4be25d3ce"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-09T11:01:39.750984Z"), envelope.IssuedAt);              
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Message), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void ExportTest1()
        {
            Envelope envelope1 = new Envelope(Commons.IssuerIdentity.SubjectId);
            envelope1.AddItem(Commons.IssuerIdentity);
            envelope1.AddItem(Commons.IssuerKey.PublicCopy());
            envelope1.Sign(Commons.IssuerKey);
            string exported = envelope1.Export();

            Envelope envelope2 = Envelope.Import(exported);
            envelope2.Verify(Commons.IssuerKey);
            Assert.AreEqual(2, envelope2.Items.Count);

            Identity identity = (Identity)envelope2.Items.ElementAt(0);
            Assert.AreEqual(Commons.IssuerIdentity.SubjectId, identity.SubjectId);
            Key keybox = (Key)envelope2.Items.ElementAt(1);
            Assert.AreEqual(Commons.IssuerKey.UniqueId, keybox.UniqueId);
            Assert.IsNull(keybox.Secret);
        }

    }

}
