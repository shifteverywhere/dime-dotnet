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
            string exported = "Di:IIR.eyJ1aWQiOiI0MTA5ZTdkZS03YmNkLTRiNzAtOWJkYy02ZmMxY2M5Mzc3ZjYiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjI5OjQwLjAyNzcyMloiLCJwdWIiOiIxaFBKUFVrOWI4VENHcGRZV0dGdm5Gd2t3aUV3cVVjWFVCY3VKU2NZY0JCa1pCbW93NTNSTSIsImNhcCI6WyJnZW5lcmljIl19.ASR3EuXKixFNWnURxBa584QWuUBmI0MGuGruLhrbXlAwiL3Mhz2iuNOHclYENLcLjdYZKfIDCemIcPtM3sODGwo";
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
            string exported = "Di.eyJpc3MiOiJlZTAwYjVlZC01YTVhLTRkMDEtOGQ1MC00ZTAzODk0ZDI1ZDQiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjI3OjU3LjcyOTIxNloifQ:ID.eyJ1aWQiOiI3NDlkNTA4Ni0xNmFhLTRhM2YtYjc1Mi0zMDYyNzBiMDg1YzUiLCJzdWIiOiJlZTAwYjVlZC01YTVhLTRkMDEtOGQ1MC00ZTAzODk0ZDI1ZDQiLCJpc3MiOiJkZDNjZmQ2ZS1hMzY2LTRiMGMtYTRlMy1hZTExZjdjZGY5NjciLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjIyOjQwLjg5MDYwMVoiLCJleHAiOiIyMDIyLTA4LTEwVDA2OjIyOjQwLjg5MDYwMVoiLCJwdWIiOiIxaFBLWm1vRnJkMVhBU2tIc3FUQWIzMnFrdlMxTlNaYU1tYzdzcWR2SzRIQTZCdXREYk5GNCIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKMWFXUWlPaUkwTldVMU1qQXhOeTB3WldJeUxUUTVOamN0T0RVeFlTMW1OVGd5WlRJMlpqUm1aak1pTENKemRXSWlPaUprWkROalptUTJaUzFoTXpZMkxUUmlNR010WVRSbE15MWhaVEV4WmpkalpHWTVOamNpTENKcGMzTWlPaUl3TUdGaE1qWmxOeTB6TkdJeUxUUm1ZVEl0WW1SbU5pMHhOMlpsWXpBNE5EQTNOamtpTENKcFlYUWlPaUl5TURJeExUQTRMVEV3VkRBMk9qRTVPalV6TGpnd01qVTFNVm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE1VkRBMk9qRTVPalV6TGpnd01qVTFNVm9pTENKd2RXSWlPaUl4YUZCTGRVVkZPSEpNYmpSd05rNUlkWG96VG1wR1VWUm1OalJWTmtoUk4wcDZPR1J4T0ZKdFdVNUNURFozVGxZelRrRnlReUlzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpTENKcGMzTjFaU0pkZlEuQVpmM1dGU29mNkRYTkhtd0ZiYUFWR2p2c09xcFhhZ1JSWnhWV0tlYW03U3graThjdDEzRmtGbVdRMk4vbGZuVHpZTTQ0dTNPc2RORVVGd3hQbmdPSHc0.AawlZOyXVbC53NP0kP33PIav0TTfyVLpVzF+7H1Bzb95iTdV8hOyLc6q2el8ZYFyvRUqXu5BNk2ibQbkc2K8igQ:AUsf4vJanreevAg0gVeqe/rj8v54G8AB+c9lgAyY433Iz11bQo/Evd/folccyAdM6gGYlT1P0mTvxtGPsZZang0";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("ee00b5ed-5a5a-4d01-8d50-4e03894d25d4"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-10T06:27:57.729216Z"), envelope.IssuedAt);          
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.IssuerKey);
        }

        [TestMethod]
        public void IdentityImportTest2()
        {
            string exported = "Di:ID.eyJ1aWQiOiI3NDlkNTA4Ni0xNmFhLTRhM2YtYjc1Mi0zMDYyNzBiMDg1YzUiLCJzdWIiOiJlZTAwYjVlZC01YTVhLTRkMDEtOGQ1MC00ZTAzODk0ZDI1ZDQiLCJpc3MiOiJkZDNjZmQ2ZS1hMzY2LTRiMGMtYTRlMy1hZTExZjdjZGY5NjciLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjIyOjQwLjg5MDYwMVoiLCJleHAiOiIyMDIyLTA4LTEwVDA2OjIyOjQwLjg5MDYwMVoiLCJwdWIiOiIxaFBLWm1vRnJkMVhBU2tIc3FUQWIzMnFrdlMxTlNaYU1tYzdzcWR2SzRIQTZCdXREYk5GNCIsImNhcCI6WyJnZW5lcmljIiwiaWRlbnRpZnkiXX0.SUQuZXlKMWFXUWlPaUkwTldVMU1qQXhOeTB3WldJeUxUUTVOamN0T0RVeFlTMW1OVGd5WlRJMlpqUm1aak1pTENKemRXSWlPaUprWkROalptUTJaUzFoTXpZMkxUUmlNR010WVRSbE15MWhaVEV4WmpkalpHWTVOamNpTENKcGMzTWlPaUl3TUdGaE1qWmxOeTB6TkdJeUxUUm1ZVEl0WW1SbU5pMHhOMlpsWXpBNE5EQTNOamtpTENKcFlYUWlPaUl5TURJeExUQTRMVEV3VkRBMk9qRTVPalV6TGpnd01qVTFNVm9pTENKbGVIQWlPaUl5TURJMkxUQTRMVEE1VkRBMk9qRTVPalV6TGpnd01qVTFNVm9pTENKd2RXSWlPaUl4YUZCTGRVVkZPSEpNYmpSd05rNUlkWG96VG1wR1VWUm1OalJWTmtoUk4wcDZPR1J4T0ZKdFdVNUNURFozVGxZelRrRnlReUlzSW1OaGNDSTZXeUpuWlc1bGNtbGpJaXdpYVdSbGJuUnBabmtpTENKcGMzTjFaU0pkZlEuQVpmM1dGU29mNkRYTkhtd0ZiYUFWR2p2c09xcFhhZ1JSWnhWV0tlYW03U3graThjdDEzRmtGbVdRMk4vbGZuVHpZTTQ0dTNPc2RORVVGd3hQbmdPSHc0.AawlZOyXVbC53NP0kP33PIav0TTfyVLpVzF+7H1Bzb95iTdV8hOyLc6q2el8ZYFyvRUqXu5BNk2ibQbkc2K8igQ";
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
            string exported = "Di.eyJpc3MiOiJlZTAwYjVlZC01YTVhLTRkMDEtOGQ1MC00ZTAzODk0ZDI1ZDQiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjI2OjUwLjM1MDAwMloifQ:KEY.eyJ1aWQiOiJjMWNkNjRmNi0wNDk4LTQxOWYtYmY2OS05MWJkYWU4NDYxYmMiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjIyOjQwLjc5NTk5MloiLCJrZXkiOiIxaEVpZ3l5N3Fva0R2ZzRWNFk1N0FKdjdkN1J3TmNGMTRMNVUzOFdWMUh1NkIxVnV2YmlSbyIsInB1YiI6IjFoUEtabW9GcmQxWEFTa0hzcVRBYjMycWt2UzFOU1phTW1jN3NxZHZLNEhBNkJ1dERiTkY0In0:AXWVbDwSD6sPORUYvw/7iMGmwoG9ZZ9x1txlY8L8kv95in4Y3jssUWvGiZnoQTseN2Fuhc2kGLngBkksDuMaxgk";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("ee00b5ed-5a5a-4d01-8d50-4e03894d25d4"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-10T06:26:50.350002Z"), envelope.IssuedAt);              
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
            string exported = "Di.eyJpc3MiOiJlZTAwYjVlZC01YTVhLTRkMDEtOGQ1MC00ZTAzODk0ZDI1ZDQiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjI1OjEzLjk4MzUyM1oifQ:MSG.eyJ1aWQiOiJhOWM1YmY2My03YWE4LTQwMzYtOTViZC1kNjUwNzNlZWU3YjgiLCJhdWQiOiJmYzFjYzhjOC0yOWUyLTQ1Y2UtYjFjMi0xNzJhOTNlNzcxZTUiLCJpc3MiOiJlZTAwYjVlZC01YTVhLTRkMDEtOGQ1MC00ZTAzODk0ZDI1ZDQiLCJpYXQiOiIyMDIxLTA4LTEwVDA2OjI1OjEzLjk4NzQ2MloiLCJleHAiOiIyMDIxLTA4LTEwVDA2OjI2OjUzLjk4NzQ2MloifQ.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.AScWtfDD0ySVfAtaFpc9hlL7fKC9mpjOsNoJaSocrooN7rjDrkQr3gGgn7VdsbdKMQzjBWFN1PAI7o65KxpsKAU:AVU/gkTPZoLCiObU8PZZxnlDDxDeUqa96u7NL8UZFfnUNrw10lLcMXSxGGOZdjw5g5kBgc6KLSzCx8Nf8V8Oaww";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("ee00b5ed-5a5a-4d01-8d50-4e03894d25d4"), envelope.IssuerId);  
            Assert.AreEqual(DateTime.Parse("2021-08-10T06:25:13.983523Z"), envelope.IssuedAt);              
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
