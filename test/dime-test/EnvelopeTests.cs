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
            string exported = "Di:IIR.eyJ1aWQiOiI4MjFjOGIwMC0xZDZhLTQ5YjAtODMyZi0yZTg1MThiMmExMzQiLCJpYXQiOjE2MjYzNzk0MjIsInB1YiI6IkNZSHQ3VkNzMnc3ak5ycGdBbjlYSlRnV2JzMTltdXJYekpVYTJwZkJFZ2hXODlidHRoaFhteiIsImNhcCI6WyJnZW5lcmljIl19.AdC3FJLc3iQQbJLiicU/dwL3dkT39CiUtQdAbPhpX0V16W1l6NljgEEMwpwcHkxxnubfmb3yaBf2CHDMX+t4+Ak";
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
            string exported = "Di.eyJpc3MiOiIzNGU3MDgxYi04ODcxLTQ2N2EtYTk2My03ZjBlZWRiNDJjODAiLCJpYXQiOjE2MjYzNzk0NTR9:ID.eyJ1aWQiOiJjNDhlNGI2OC05MWFjLTRjOTMtYmE5Ni0xYzM1YzUwNzYxZDQiLCJzdWIiOiIzNGU3MDgxYi04ODcxLTQ2N2EtYTk2My03ZjBlZWRiNDJjODAiLCJpc3MiOiI2NDc1ODliZi03ZjdlLTRkNGMtODE3NC1lM2ViMzY2ZDVhOTEiLCJpYXQiOjE2MjYzNzg0OTYsImV4cCI6MTY1NzkxNDQ5NiwicHViIjoiQ1lIdDdnWVdqek54NXV6eWNmTjE4WVIxUjJMUEVmNTVoQWt1TkFCd0t3QXhBTkFia1pzOWR3IiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.SUQuZXlKMWFXUWlPaUprTWpjMVpESmpNeTAzWkRGbUxUUTBZVEV0T0Rjd1pTMHpPRFEyT1dWaU1EUmhORFVpTENKemRXSWlPaUkyTkRjMU9EbGlaaTAzWmpkbExUUmtOR010T0RFM05DMWxNMlZpTXpZMlpEVmhPVEVpTENKcGMzTWlPaUpqWVROaE1HWTFZeTAyTUdVeExUUmtZemd0WVRSaE9TMDNZVGd3T0Rrek5qTTVaV1lpTENKcFlYUWlPakUyTWpZek56Z3pNRFVzSW1WNGNDSTZNVGM0TkRBMU9ETXdOU3dpY0hWaUlqb2lRMWxJZERadFFXSldNemxwVG5kTVFrRkJWRTV0WTJaM2IwUTBWbTE1VUd0a2NFWldTa3RtU0RGTlJuSnpVRmN6WjNkMk1VcHlJaXdpWTJGd0lqcGJJbWRsYm1WeWFXTWlMQ0pwWkdWdWRHbG1lU0lzSW1semMzVmxJbDE5LkFhdmZLZzFXMTM1cndHamozMVZoNE5DMkM5N044QTE0ZDFWb1R1MGVnWElmK0s5N0lYdWxvYXJhY08zR1FUb044SHB2VjNMeVFPV0I2OHNnUHU1T3ZRcw.AavQrK+J3jQ+sEJKoFbh12aA0vhx4z7n3FijXsF9AOOLFNkmZSelEbdPxJ3A2VFrfHEaT5/GzB5LYcJ0jUbihgQ:AbSqUUeHdC7J9oicX9eoiY5EenzKyLVa6CsVIIlgwhO2qfTVZsERU5KXuHvVZF6Qmj/RGeSfNFS7TESIt5PFaQg";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("34e7081b-8871-467a-a963-7f0eedb42c80"), envelope.IssuerId);  
            Assert.AreEqual(1626379454, envelope.IssuedAt);          
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Identity), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.SenderKey);
        }

        [TestMethod]
        public void IdentityImportTest2()
        {
            string exported = "Di:ID.eyJ1aWQiOiJjNDhlNGI2OC05MWFjLTRjOTMtYmE5Ni0xYzM1YzUwNzYxZDQiLCJzdWIiOiIzNGU3MDgxYi04ODcxLTQ2N2EtYTk2My03ZjBlZWRiNDJjODAiLCJpc3MiOiI2NDc1ODliZi03ZjdlLTRkNGMtODE3NC1lM2ViMzY2ZDVhOTEiLCJpYXQiOjE2MjYzNzg0OTYsImV4cCI6MTY1NzkxNDQ5NiwicHViIjoiQ1lIdDdnWVdqek54NXV6eWNmTjE4WVIxUjJMUEVmNTVoQWt1TkFCd0t3QXhBTkFia1pzOWR3IiwiY2FwIjpbImdlbmVyaWMiLCJpZGVudGlmeSJdfQ.SUQuZXlKMWFXUWlPaUprTWpjMVpESmpNeTAzWkRGbUxUUTBZVEV0T0Rjd1pTMHpPRFEyT1dWaU1EUmhORFVpTENKemRXSWlPaUkyTkRjMU9EbGlaaTAzWmpkbExUUmtOR010T0RFM05DMWxNMlZpTXpZMlpEVmhPVEVpTENKcGMzTWlPaUpqWVROaE1HWTFZeTAyTUdVeExUUmtZemd0WVRSaE9TMDNZVGd3T0Rrek5qTTVaV1lpTENKcFlYUWlPakUyTWpZek56Z3pNRFVzSW1WNGNDSTZNVGM0TkRBMU9ETXdOU3dpY0hWaUlqb2lRMWxJZERadFFXSldNemxwVG5kTVFrRkJWRTV0WTJaM2IwUTBWbTE1VUd0a2NFWldTa3RtU0RGTlJuSnpVRmN6WjNkMk1VcHlJaXdpWTJGd0lqcGJJbWRsYm1WeWFXTWlMQ0pwWkdWdWRHbG1lU0lzSW1semMzVmxJbDE5LkFhdmZLZzFXMTM1cndHamozMVZoNE5DMkM5N044QTE0ZDFWb1R1MGVnWElmK0s5N0lYdWxvYXJhY08zR1FUb044SHB2VjNMeVFPV0I2OHNnUHU1T3ZRcw.AavQrK+J3jQ+sEJKoFbh12aA0vhx4z7n3FijXsF9AOOLFNkmZSelEbdPxJ3A2VFrfHEaT5/GzB5LYcJ0jUbihgQ";
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
        public void KeyBoxExportTest1()
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
        public void KeyBoxImportTest1()
        {
            string exported = "Di.eyJpc3MiOiIzNGU3MDgxYi04ODcxLTQ2N2EtYTk2My03ZjBlZWRiNDJjODAiLCJpYXQiOjE2MjYzNzk1MjZ9:KEY.eyJraWQiOiI3MTc1NzFhMC0wNmY0LTQzZDUtYWUwMi00ZDMzMjQwMDExNDYiLCJpYXQiOjE2MjYzNzg0OTYsImtleSI6IkNZSGpYOWtOZUttdU1tb3Jwb1JhcDVCQUpjTDNOZTZEelZXaU56cjJBVHh4NlF5Y2pvZ3duVyIsInB1YiI6IkNZSHQ3Z1lXanpOeDV1enljZk4xOFlSMVIyTFBFZjU1aEFrdU5BQndLd0F4QU5BYmtaczlkdyJ9:AWAFPW7PYSKTueG4DM5rpw3RnpXn4jDB9QIlrlAiW1PczdkAKEdKaUNOzjaqsVTGGtl2bhekHd4Xp7k84GWVUws";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("34e7081b-8871-467a-a963-7f0eedb42c80"), envelope.IssuerId);  
            Assert.AreEqual(1626379526, envelope.IssuedAt);              
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
            string exported = "Di.eyJpc3MiOiIzNGU3MDgxYi04ODcxLTQ2N2EtYTk2My03ZjBlZWRiNDJjODAiLCJpYXQiOjE2MjYzNzk1NzF9:MSG.eyJ1aWQiOiJmZmZiNzQzMi0xNDIzLTQ0ZjgtYTVlMi1iMjQ3YWVlODlkM2UiLCJhdWQiOiIwZTMyZGY2Zi0xNjg3LTQwNTktODIyOS0yM2E2NzlhODExYzkiLCJpc3MiOiIzNGU3MDgxYi04ODcxLTQ2N2EtYTk2My03ZjBlZWRiNDJjODAiLCJpYXQiOjE2MjYzNzk1NzEsImV4cCI6MTYyNjM3OTY3MX0.UmFjZWNhciBpcyByYWNlY2FyIGJhY2t3YXJkcy4.AQaEBh1mi8tSw0AltZqgINy9RWGCjbiInN1OiWqtu++iuMV+ETIzq8sfs/iILyY69Z8rD1BmluzYyj9/DFnmyAI:AcmHztff2RGQT33tYz4Cvx0oOamTsrnRJZfCNqo0okt1tyNcJGVhEM1nXp16Y7QgRvw88CYDi0DTKA29SbEvrgE";
            Envelope envelope = Envelope.Import(exported);
            Assert.IsFalse(envelope.IsAnonymous);
            Assert.AreEqual(new Guid("34e7081b-8871-467a-a963-7f0eedb42c80"), envelope.IssuerId);  
            Assert.AreEqual(1626379571, envelope.IssuedAt);              
            Assert.AreEqual(1, envelope.Items.Count);
            Assert.AreEqual(typeof(Message), envelope.Items.ElementAt(0).GetType());
            envelope.Verify(Commons.SenderKey);
        }

        [TestMethod]
        public void ExportTest1()
        {
            Envelope envelope1 = new Envelope(Commons.SenderIdentity.SubjectId);
            envelope1.AddItem(Commons.SenderIdentity);
            envelope1.AddItem(Commons.SenderKey.PublicOnly());
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
